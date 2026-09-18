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

use std::borrow::Cow;
use std::collections::VecDeque;

use bitvec::field::BitField;
use chrono::{DateTime, FixedOffset};
use telcom_parser::lte_rrc::{
    BCCH_DL_SCH_MessageType, BCCH_DL_SCH_MessageType_c1, SystemInformationBlockType1,
};

use super::analyzer::{Analyzer, Event, EventType};
use super::information_element::{InformationElement, LteInformationElement};
use crate::diag::diaglog::ml1;
use crate::plmn::format_rrc_plmn_list;

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
        }
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

        let min = self.rsrp_window.iter().copied().fold(f32::INFINITY, f32::min);
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
        let event_type = if self.neighbor_streak_flagged {
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

    fn on_neighbor_measurement(&mut self, meas: &ml1::neighbor_cells::Measurements) -> Option<Event> {
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

        let event_type = if self.signal_anomaly_flagged_for_pci.is_some() {
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
             and/or a persistently empty or tiny neighbor-cell list. Either signal alone is \
             common in ordinary circumstances -- very close to a legitimate tower, or genuinely \
             rural/low-density coverage -- so this heuristic reports each at low severity alone \
             and escalates only when both are currently true for the same cell.",
        )
    }

    fn get_version(&self) -> u32 {
        1
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
        match &**lte_ie {
            LteInformationElement::BcchDlSch(sch_msg) => {
                if let BCCH_DL_SCH_MessageType::C1(c1) = &sch_msg.message
                    && let BCCH_DL_SCH_MessageType_c1::SystemInformationBlockType1(sib1) = c1
                {
                    self.last_cell_identity = Some(Self::cell_identity_from_sib1(sib1));
                }
                None
            }
            LteInformationElement::Ml1ServingCell(meas) => self.on_serving_measurement(meas),
            LteInformationElement::Ml1NeighborCells(meas) => self.on_neighbor_measurement(meas),
            _ => None,
        }
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
}
