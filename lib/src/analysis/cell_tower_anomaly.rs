//! Looks for signs of a *passive* cell-site simulator: one that doesn't
//! force a 2G downgrade or disable encryption (which the other analyzers
//! already catch), and instead just sits there collecting identifiers.
//!
//! This heuristic combines two weak, individually-unreliable signals from
//! the modem's raw LTE ML1 radio measurements (see
//! `lib/src/diag/diaglog/ml1.rs`), which aren't otherwise surfaced anywhere:
//!
//! - An unusually strong *and* suspiciously stable serving-cell signal. A
//!   real macro cell's signal varies with multipath and movement; a rogue
//!   device sitting close to the target usually doesn't.
//! - A persistently empty or single-entry neighbor-cell list. A real tower
//!   in populated areas almost always reports several neighbors.
//!
//! Either one alone is common in ordinary circumstances (very close to a
//! legitimate tower, or genuinely rural/low-density coverage), so each is
//! reported at low severity on its own and escalated only when both are
//! currently true for the same serving cell -- matching this project's
//! general preference for combining weak signals over trusting any single
//! naive check (see e.g. the IMSI Requested and Incomplete SIB analyzers).
//!
//! ## A caveat worth being upfront about
//!
//! ML1 measurements identify a cell only by PCI (Physical Cell ID), which is
//! locally unique, not globally unique. The true global identity (used here
//! only to label events, not to key the heuristics) comes from SIB1
//! broadcasts instead. This analyzer correlates the two by assuming the
//! most recently decoded SIB1 belongs to whichever cell ML1 currently calls
//! "serving" -- true the vast majority of the time, but briefly wrong during
//! a handover. That only affects the cell label in the event message, not
//! whether the heuristic fires.
//!
//! ## A third signal: GPS vs. registered tower location
//!
//! When a GPS fix is available (see `gps_mode` in the daemon config) and the
//! serving cell is found in the bundled OpenCellID snapshot (see
//! [`crate::analysis::opencellid`]), this also flags a large mismatch
//! between your actual position and the cell's registered location. Unlike
//! the two signals above, this one is reported at meaningful severity on its
//! own -- a real position mismatch against a real database entry is a
//! stronger signal than either weak heuristic alone -- though OpenCellID
//! data can itself be stale or simply wrong, so it's not proof by itself
//! either. A cell that's absent from the database entirely is *not* used as
//! a signal on its own (coverage is too incomplete for that to be
//! meaningful); it only nudges up the severity of the other two signals
//! when they're already firing for the same cell.

use std::borrow::Cow;
use std::collections::VecDeque;
use std::sync::{Arc, RwLock as StdRwLock};

use bitvec::field::BitField;
use chrono::{DateTime, FixedOffset};
use serde::Serialize;
use telcom_parser::lte_rrc::{
    BCCH_DL_SCH_MessageType, BCCH_DL_SCH_MessageType_c1, SystemInformationBlockType1,
};

use super::analyzer::{Analyzer, Event, EventType};
use super::information_element::{InformationElement, LteInformationElement};
use super::opencellid::{self, Tower};
use crate::diag::diaglog::ml1;
use crate::plmn::format_rrc_plmn_list;

/// The registered tower nearest to the current serving cell (per the
/// bundled OpenCellID snapshot), and how far the live GPS fix is from it.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[cfg_attr(feature = "apidocs", derive(utoipa::ToSchema))]
pub struct MatchedTowerStatus {
    pub lat: f64,
    pub lon: f64,
    /// OpenCellID's estimated coverage radius, in meters.
    pub range_m: u32,
    /// Distance from the current GPS fix to `(lat, lon)`, in meters.
    pub distance_m: f64,
}

/// A live snapshot of what this analyzer currently knows about the serving
/// cell, for display in the daemon's web UI (`GET /api/cell-status`) rather
/// than the warnings feed. Updated on every relevant packet; not persisted
/// anywhere, and unrelated to whether any [Event] has fired.
#[derive(Clone, Debug, Default, Serialize)]
#[cfg_attr(feature = "apidocs", derive(utoipa::ToSchema))]
pub struct CellStatus {
    pub plmn: Option<String>,
    pub tac: Option<u16>,
    pub eci: Option<u32>,
    pub pci: Option<u16>,
    pub rsrp_dbm: Option<f32>,
    pub neighbor_count: Option<usize>,
    pub matched_tower: Option<MatchedTowerStatus>,
    /// True once the current cell has been looked up and wasn't found in
    /// the bundled OpenCellID snapshot -- distinct from `matched_tower`
    /// being `None` because no cell has been seen yet at all.
    pub cell_unknown_to_opencellid: bool,
}

/// Shared, thread-safe handle to a [CellStatus] snapshot. A plain
/// `std::sync::RwLock` rather than `tokio::sync::RwLock`, since it's
/// written from the synchronous [Analyzer] trait method and only ever held
/// for a trivial, non-blocking read or write.
pub type SharedCellStatus = Arc<StdRwLock<CellStatus>>;

/// Consecutive serving-cell RSRP samples kept for the stability check.
const RSRP_WINDOW: usize = 12;
/// Minimum samples in the window before judging stability at all.
const MIN_RSRP_SAMPLES: usize = 8;
/// RSRP (dBm) above which a signal counts as "unusually strong" for a macro
/// cell, as opposed to being right next to a small rogue device.
const STRONG_RSRP_DBM: f32 = -65.0;
/// Max spread (dB) across the window to call the signal "suspiciously
/// stable" -- ordinary multipath/movement produces more variance than this.
const STABLE_SPREAD_DB: f32 = 3.0;
/// Consecutive neighbor-cell reports with <=1 neighbor before flagging.
const NEIGHBOR_STREAK_THRESHOLD: u32 = 10;
/// Minimum GPS-to-registered-tower distance (meters) before flagging a
/// mismatch, regardless of the tower's own estimated coverage radius.
const GPS_MISMATCH_MIN_METERS: f64 = 5_000.0;
/// How generously to scale the tower's own OpenCellID range estimate before
/// treating it as a mismatch -- those estimates are often crude, derived
/// from sparse crowdsourced samples, so this errs on the side of not flagging.
const GPS_MISMATCH_RANGE_MULTIPLIER: f64 = 3.0;

#[derive(Clone)]
struct CellIdentitySummary {
    plmns: Vec<String>,
    tac: u16,
    eci: u32,
}

impl std::fmt::Display for CellIdentitySummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PLMN {} TAC {} ECI {}",
            self.plmns.join("/"),
            self.tac,
            self.eci
        )
    }
}

pub struct CellTowerAnomalyAnalyzer {
    /// Cell identity from the most recently decoded SIB1. See the module
    /// doc comment for how (and how loosely) this is correlated with the
    /// ML1 measurements below.
    last_cell_identity: Option<CellIdentitySummary>,

    serving_pci: Option<u16>,
    rsrp_window: VecDeque<f32>,
    signal_anomaly_flagged_for_pci: Option<u16>,

    neighbor_streak: u32,
    neighbor_streak_flagged: bool,
    last_neighbor_count: Option<usize>,

    /// Latest GPS fix, if any -- see [Analyzer::set_gps].
    current_gps: Option<(f64, f64)>,
    /// The ECI we last ran an OpenCellID lookup for, so we don't repeat the
    /// lookup on every repeated SIB1 broadcast of the same cell.
    matched_eci: Option<u32>,
    matched_tower: Option<&'static Tower>,
    /// True once we've looked up the current cell and it wasn't in the
    /// bundled OpenCellID snapshot. Never a standalone signal (see the
    /// module doc comment) -- only nudges the other two signals' severity.
    cell_unknown_to_opencellid: bool,
    gps_mismatch_flagged_for_eci: Option<u32>,

    /// See [CellStatus] and [Self::status_handle].
    status: SharedCellStatus,
}

impl Default for CellTowerAnomalyAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl CellTowerAnomalyAnalyzer {
    pub fn new() -> Self {
        Self {
            last_cell_identity: None,
            serving_pci: None,
            rsrp_window: VecDeque::with_capacity(RSRP_WINDOW),
            signal_anomaly_flagged_for_pci: None,
            neighbor_streak: 0,
            neighbor_streak_flagged: false,
            last_neighbor_count: None,
            current_gps: None,
            matched_eci: None,
            matched_tower: None,
            cell_unknown_to_opencellid: false,
            gps_mismatch_flagged_for_eci: None,
            status: Arc::new(StdRwLock::new(CellStatus::default())),
        }
    }

    /// A clone of the handle this analyzer publishes its live [CellStatus]
    /// to. Callers (e.g. the daemon's HTTP layer) should grab this right
    /// after construction, since each new recording constructs a fresh
    /// analyzer with its own status handle.
    pub fn status_handle(&self) -> SharedCellStatus {
        self.status.clone()
    }

    fn publish_status(&self) {
        let matched_tower = self.matched_tower.and_then(|tower| {
            self.current_gps.map(|(lat, lon)| MatchedTowerStatus {
                lat: tower.lat,
                lon: tower.lon,
                range_m: tower.range_m,
                distance_m: opencellid::distance_meters(lat, lon, tower.lat, tower.lon),
            })
        });
        let status = CellStatus {
            plmn: self
                .last_cell_identity
                .as_ref()
                .and_then(|c| c.plmns.first().cloned()),
            tac: self.last_cell_identity.as_ref().map(|c| c.tac),
            eci: self.last_cell_identity.as_ref().map(|c| c.eci),
            pci: self.serving_pci,
            rsrp_dbm: self.rsrp_window.back().copied(),
            neighbor_count: self.last_neighbor_count,
            matched_tower,
            cell_unknown_to_opencellid: self.cell_unknown_to_opencellid,
        };
        if let Ok(mut guard) = self.status.write() {
            *guard = status;
        }
    }

    /// True if either of the other two signals is currently active for the
    /// present cell, or the cell is simply unknown to OpenCellID -- used to
    /// decide whether to escalate severity.
    fn other_signals_active(&self) -> bool {
        self.signal_anomaly_flagged_for_pci.is_some()
            || self.neighbor_streak_flagged
            || self.cell_unknown_to_opencellid
    }

    /// Looks up the current cell in the OpenCellID index (once per distinct
    /// cell) and, if we also have a GPS fix, checks it against the tower's
    /// registered location. Called every time a SIB1 is decoded, since GPS
    /// fixes and cell identities can each arrive first.
    fn evaluate_tower_match(&mut self) -> Option<Event> {
        let identity = self.last_cell_identity.clone()?;

        if self.matched_eci != Some(identity.eci) {
            self.matched_eci = Some(identity.eci);
            self.gps_mismatch_flagged_for_eci = None;
            self.matched_tower = identity
                .plmns
                .iter()
                .find_map(|plmn| opencellid::INDEX.lookup(plmn, identity.eci));
            self.cell_unknown_to_opencellid = self.matched_tower.is_none();
        }

        let tower = self.matched_tower?;
        let (lat, lon) = self.current_gps?;
        if self.gps_mismatch_flagged_for_eci == Some(identity.eci) {
            return None;
        }

        let distance_m = opencellid::distance_meters(lat, lon, tower.lat, tower.lon);
        let threshold_m =
            (tower.range_m as f64 * GPS_MISMATCH_RANGE_MULTIPLIER).max(GPS_MISMATCH_MIN_METERS);
        if distance_m <= threshold_m {
            return None;
        }

        self.gps_mismatch_flagged_for_eci = Some(identity.eci);
        let event_type = if self.other_signals_active() {
            EventType::High
        } else {
            EventType::Medium
        };
        Some(Event {
            event_type,
            message: format!(
                "Serving cell ({identity}) is registered near ({:.4}, {:.4}) in OpenCellID, but \
                 your current GPS position is {:.1} km away -- far outside its ~{:.1} km \
                 estimated coverage radius. OpenCellID data can be stale or simply wrong for a \
                 given cell, so treat this as a lead to investigate, not proof on its own.",
                tower.lat,
                tower.lon,
                distance_m / 1000.0,
                tower.range_m as f64 / 1000.0,
            ),
        })
    }

    fn cell_identity_from_sib1(sib1: &SystemInformationBlockType1) -> CellIdentitySummary {
        let info = &sib1.cell_access_related_info;
        CellIdentitySummary {
            plmns: format_rrc_plmn_list(&info.plmn_identity_list),
            tac: info.tracking_area_code.0.load_be::<u16>(),
            eci: info.cell_identity.0.load_be::<u32>(),
        }
    }

    fn cell_label(&self) -> String {
        self.last_cell_identity
            .as_ref()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "cell identity not yet seen".to_string())
    }

    fn on_serving_measurement(
        &mut self,
        meas: &ml1::serving_cell::MeasurementAndEvaluation,
    ) -> Option<Event> {
        let pci = meas.get_pci();
        if self.serving_pci != Some(pci) {
            // New serving cell (or the first one we've seen): start a fresh
            // baseline instead of comparing signal stability across a
            // handover, which would naturally look unstable.
            self.serving_pci = Some(pci);
            self.rsrp_window.clear();
            self.signal_anomaly_flagged_for_pci = None;
        }

        self.rsrp_window.push_back(meas.get_meas_rsrp());
        if self.rsrp_window.len() > RSRP_WINDOW {
            self.rsrp_window.pop_front();
        }

        if self.rsrp_window.len() < MIN_RSRP_SAMPLES
            || self.signal_anomaly_flagged_for_pci == Some(pci)
        {
            return None;
        }

        let min = self
            .rsrp_window
            .iter()
            .copied()
            .fold(f32::INFINITY, f32::min);
        let max = self
            .rsrp_window
            .iter()
            .copied()
            .fold(f32::NEG_INFINITY, f32::max);
        let mean: f32 = self.rsrp_window.iter().sum::<f32>() / self.rsrp_window.len() as f32;
        let spread = max - min;

        if mean <= STRONG_RSRP_DBM || spread >= STABLE_SPREAD_DB {
            return None;
        }

        self.signal_anomaly_flagged_for_pci = Some(pci);
        let event_type = if self.neighbor_streak_flagged || self.cell_unknown_to_opencellid {
            EventType::Medium
        } else {
            EventType::Low
        };
        Some(Event {
            event_type,
            message: format!(
                "Serving cell (PCI {pci}, {}) has an unusually strong signal ({mean:.1} dBm \
                 average) that's suspiciously stable (only {spread:.1} dB of variance over {} \
                 samples). This alone can happen legitimately very close to a tower -- treat it \
                 as suspicious mainly if it's paired with other warnings.",
                self.cell_label(),
                self.rsrp_window.len(),
            ),
        })
    }

    fn on_neighbor_measurement(
        &mut self,
        meas: &ml1::neighbor_cells::Measurements,
    ) -> Option<Event> {
        self.last_neighbor_count = Some(meas.cells.len());
        if meas.cells.len() > 1 {
            self.neighbor_streak = 0;
            self.neighbor_streak_flagged = false;
            return None;
        }
        self.neighbor_streak += 1;

        if self.neighbor_streak != NEIGHBOR_STREAK_THRESHOLD || self.neighbor_streak_flagged {
            return None;
        }
        self.neighbor_streak_flagged = true;

        let event_type =
            if self.signal_anomaly_flagged_for_pci.is_some() || self.cell_unknown_to_opencellid {
                EventType::Medium
            } else {
                EventType::Informational
            };
        Some(Event {
            event_type,
            message: format!(
                "Serving cell ({}) has reported {} neighbor cell(s) for {} consecutive \
                 measurements. This is common in genuinely rural or low-density coverage on its \
                 own -- it's only meaningful combined with other warnings.",
                self.cell_label(),
                meas.cells.len(),
                self.neighbor_streak,
            ),
        })
    }
}

impl Analyzer for CellTowerAnomalyAnalyzer {
    fn get_name(&self) -> Cow<'_, str> {
        Cow::from("Cell Tower Anomaly")
    }

    fn get_description(&self) -> Cow<'_, str> {
        Cow::from(
            "Looks for passive cell-site-simulator behavior that doesn't force a downgrade or \
             disable encryption: an unusually strong and suspiciously stable serving-cell signal, \
             a persistently empty or tiny neighbor-cell list, and/or (when a GPS fix and an \
             OpenCellID match are both available) your position being far from the serving \
             cell's registered location. The first two are common in ordinary circumstances -- \
             very close to a legitimate tower, or genuinely rural/low-density coverage -- so \
             they're reported at low severity alone and escalated only when combined with each \
             other or a GPS mismatch for the same cell.",
        )
    }

    fn get_version(&self) -> u32 {
        2
    }

    fn set_gps(&mut self, lat: f64, lon: f64) {
        self.current_gps = Some((lat, lon));
        self.publish_status();
    }

    fn analyze_information_element(
        &mut self,
        ie: &InformationElement,
        _packet_num: usize,
        _timestamp: DateTime<FixedOffset>,
    ) -> Option<Event> {
        let InformationElement::LTE(lte_ie) = ie else {
            return None;
        };
        let event = match &**lte_ie {
            LteInformationElement::BcchDlSch(sch_msg) => {
                if let BCCH_DL_SCH_MessageType::C1(c1) = &sch_msg.message
                    && let BCCH_DL_SCH_MessageType_c1::SystemInformationBlockType1(sib1) = c1
                {
                    self.last_cell_identity = Some(Self::cell_identity_from_sib1(sib1));
                    self.evaluate_tower_match()
                } else {
                    None
                }
            }
            LteInformationElement::Ml1ServingCell(meas) => self.on_serving_measurement(meas),
            LteInformationElement::Ml1NeighborCells(meas) => self.on_neighbor_measurement(meas),
            _ => None,
        };
        self.publish_status();
        event
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn ts() -> DateTime<FixedOffset> {
        Utc::now().into()
    }

    fn serving_ie(pci: u16, rsrp_dbm: f32) -> InformationElement {
        InformationElement::LTE(Box::new(LteInformationElement::Ml1ServingCell(
            ml1::serving_cell::test_measurement(pci, rsrp_dbm),
        )))
    }

    fn neighbors_ie(n_cells: usize) -> InformationElement {
        InformationElement::LTE(Box::new(LteInformationElement::Ml1NeighborCells(
            ml1::neighbor_cells::test_measurements(n_cells),
        )))
    }

    #[test]
    fn flags_a_strong_stable_signal() {
        let mut analyzer = CellTowerAnomalyAnalyzer::new();
        let mut events = vec![];
        for _ in 0..MIN_RSRP_SAMPLES {
            events.push(analyzer.analyze_information_element(&serving_ie(99, -60.0), 0, ts()));
        }
        assert_eq!(
            events.iter().filter(|e| e.is_some()).count(),
            1,
            "should fire exactly once, on the sample that crosses MIN_RSRP_SAMPLES"
        );
        let event = events.into_iter().flatten().next().unwrap();
        assert_eq!(event.event_type, EventType::Low);

        // Shouldn't re-fire for the same cell once already flagged.
        for _ in 0..5 {
            assert!(
                analyzer
                    .analyze_information_element(&serving_ie(99, -60.0), 0, ts())
                    .is_none()
            );
        }
    }

    #[test]
    fn does_not_flag_a_weak_signal() {
        let mut analyzer = CellTowerAnomalyAnalyzer::new();
        for _ in 0..MIN_RSRP_SAMPLES + 5 {
            assert!(
                analyzer
                    .analyze_information_element(&serving_ie(99, -101.25), 0, ts())
                    .is_none()
            );
        }
    }

    #[test]
    fn does_not_flag_an_unstable_strong_signal() {
        let mut analyzer = CellTowerAnomalyAnalyzer::new();
        for i in 0..MIN_RSRP_SAMPLES + 5 {
            // Alternates between -60 and -50 dBm: strong, but not stable.
            let rsrp = if i % 2 == 0 { -60.0 } else { -50.0 };
            assert!(
                analyzer
                    .analyze_information_element(&serving_ie(99, rsrp), 0, ts())
                    .is_none()
            );
        }
    }

    #[test]
    fn a_new_pci_resets_the_baseline() {
        let mut analyzer = CellTowerAnomalyAnalyzer::new();
        for _ in 0..MIN_RSRP_SAMPLES {
            analyzer.analyze_information_element(&serving_ie(1, -60.0), 0, ts());
        }
        // Handover to a new cell: even though it's also strong, the window
        // should reset rather than immediately firing on stale samples.
        assert!(
            analyzer
                .analyze_information_element(&serving_ie(2, -60.0), 0, ts())
                .is_none()
        );
    }

    #[test]
    fn flags_a_persistently_empty_neighbor_list() {
        let mut analyzer = CellTowerAnomalyAnalyzer::new();
        let mut events = vec![];
        for _ in 0..NEIGHBOR_STREAK_THRESHOLD {
            events.push(analyzer.analyze_information_element(&neighbors_ie(0), 0, ts()));
        }
        assert_eq!(events.iter().filter(|e| e.is_some()).count(), 1);
        let event = events.into_iter().flatten().next().unwrap();
        assert_eq!(event.event_type, EventType::Informational);
    }

    #[test]
    fn a_normal_neighbor_report_resets_the_streak() {
        let mut analyzer = CellTowerAnomalyAnalyzer::new();
        for _ in 0..(NEIGHBOR_STREAK_THRESHOLD - 1) {
            analyzer.analyze_information_element(&neighbors_ie(0), 0, ts());
        }
        assert!(
            analyzer
                .analyze_information_element(&neighbors_ie(5), 0, ts())
                .is_none()
        );
        for _ in 0..(NEIGHBOR_STREAK_THRESHOLD - 1) {
            assert!(
                analyzer
                    .analyze_information_element(&neighbors_ie(0), 0, ts())
                    .is_none()
            );
        }
    }

    #[test]
    fn escalates_when_both_signals_are_active() {
        let mut analyzer = CellTowerAnomalyAnalyzer::new();
        for _ in 0..MIN_RSRP_SAMPLES {
            analyzer.analyze_information_element(&serving_ie(1, -60.0), 0, ts());
        }
        let mut events = vec![];
        for _ in 0..NEIGHBOR_STREAK_THRESHOLD {
            events.push(analyzer.analyze_information_element(&neighbors_ie(0), 0, ts()));
        }
        let event = events.into_iter().flatten().next().unwrap();
        assert_eq!(
            event.event_type,
            EventType::Medium,
            "should escalate above Informational once the signal anomaly is also active"
        );
    }

    // First data row of the bundled middle_tn_towers.csv:
    // LTE,310,410,8840,41733647,0,-86.7354,36.2672,8495,35,1,...
    const KNOWN_ECI: u32 = 41733647;
    const KNOWN_PLMN: &str = "310-410";
    const KNOWN_LAT: f64 = 36.2672;
    const KNOWN_LON: f64 = -86.7354;

    fn set_cell_identity(analyzer: &mut CellTowerAnomalyAnalyzer, plmn: &str, eci: u32) {
        analyzer.last_cell_identity = Some(CellIdentitySummary {
            plmns: vec![plmn.to_string()],
            tac: 1,
            eci,
        });
    }

    #[test]
    fn flags_a_gps_tower_mismatch() {
        let mut analyzer = CellTowerAnomalyAnalyzer::new();
        set_cell_identity(&mut analyzer, KNOWN_PLMN, KNOWN_ECI);
        // New York City -- nowhere near middle Tennessee.
        analyzer.set_gps(40.7128, -74.0060);

        let event = analyzer
            .evaluate_tower_match()
            .expect("should flag a huge GPS/tower mismatch");
        assert_eq!(event.event_type, EventType::Medium);
        assert!(event.message.contains(KNOWN_PLMN));

        // Shouldn't re-fire for the same cell once already flagged.
        assert!(analyzer.evaluate_tower_match().is_none());
    }

    #[test]
    fn does_not_flag_when_gps_matches_the_tower() {
        let mut analyzer = CellTowerAnomalyAnalyzer::new();
        set_cell_identity(&mut analyzer, KNOWN_PLMN, KNOWN_ECI);
        analyzer.set_gps(KNOWN_LAT, KNOWN_LON);
        assert!(analyzer.evaluate_tower_match().is_none());
    }

    #[test]
    fn does_not_flag_alone_when_cell_is_unknown_to_opencellid() {
        let mut analyzer = CellTowerAnomalyAnalyzer::new();
        set_cell_identity(&mut analyzer, KNOWN_PLMN, u32::MAX);
        analyzer.set_gps(40.7128, -74.0060);
        assert!(
            analyzer.evaluate_tower_match().is_none(),
            "a cell missing from the DB should never be a standalone signal"
        );
        assert!(analyzer.cell_unknown_to_opencellid);
    }

    #[test]
    fn unknown_cell_escalates_the_signal_anomaly() {
        let mut analyzer = CellTowerAnomalyAnalyzer::new();
        set_cell_identity(&mut analyzer, KNOWN_PLMN, u32::MAX);
        analyzer.evaluate_tower_match(); // sets cell_unknown_to_opencellid

        let mut events = vec![];
        for _ in 0..MIN_RSRP_SAMPLES {
            events.push(analyzer.analyze_information_element(&serving_ie(1, -60.0), 0, ts()));
        }
        let event = events.into_iter().flatten().next().unwrap();
        assert_eq!(
            event.event_type,
            EventType::Medium,
            "an unknown cell should escalate the signal-strength heuristic same as the \
             neighbor-list one does"
        );
    }

    #[test]
    fn without_a_gps_fix_nothing_fires() {
        let mut analyzer = CellTowerAnomalyAnalyzer::new();
        set_cell_identity(&mut analyzer, KNOWN_PLMN, KNOWN_ECI);
        assert!(analyzer.evaluate_tower_match().is_none());
    }

    #[test]
    fn publishes_a_live_status_snapshot() {
        let mut analyzer = CellTowerAnomalyAnalyzer::new();
        let status = analyzer.status_handle();
        assert!(
            status.read().unwrap().pci.is_none(),
            "should start out empty"
        );

        analyzer.analyze_information_element(&serving_ie(42, -80.0), 0, ts());
        analyzer.analyze_information_element(&neighbors_ie(3), 0, ts());
        set_cell_identity(&mut analyzer, KNOWN_PLMN, KNOWN_ECI);
        analyzer.set_gps(KNOWN_LAT, KNOWN_LON);
        analyzer.evaluate_tower_match();
        analyzer.publish_status();

        let snapshot = status.read().unwrap();
        assert_eq!(snapshot.pci, Some(42));
        assert_eq!(snapshot.rsrp_dbm, Some(-80.0));
        assert_eq!(snapshot.neighbor_count, Some(3));
        assert_eq!(snapshot.plmn.as_deref(), Some(KNOWN_PLMN));
        assert_eq!(snapshot.eci, Some(KNOWN_ECI));
        let tower = snapshot
            .matched_tower
            .as_ref()
            .expect("should have matched the known tower");
        assert_eq!(tower.lat, KNOWN_LAT);
        assert_eq!(tower.lon, KNOWN_LON);
        assert_eq!(tower.distance_m, 0.0);
        assert!(!snapshot.cell_unknown_to_opencellid);
    }
}
