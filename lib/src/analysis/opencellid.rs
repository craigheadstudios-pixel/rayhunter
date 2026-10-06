//! A small offline lookup of known cell tower locations, built at compile
//! time from a regional OpenCellID CSV export (`opencellid/*.csv`, in the
//! standard OpenCellID export schema:
//! `radio,mcc,net,area,cell,unit,lon,lat,range,samples,changeable,created,updated,averageSignal`).
//!
//! This is deliberately a static, compiled-in snapshot rather than something
//! downloaded or updated at runtime -- OpenCellID coverage is inherently
//! incomplete and grows stale, so treat a lookup miss as "unknown," never as
//! "this cell doesn't really exist." See [`crate::analysis::cell_tower_anomaly`]
//! for how misses are (and aren't) used.
//!
//! To rescope this to a different region: export a CSV covering your area
//! from <https://opencellid.org/downloads.php> (or filter a full country
//! dump), replace the file below, and rebuild.

use std::collections::HashMap;
use std::sync::LazyLock;

const CSV_DATA: &str = include_str!("opencellid/middle_tn_towers.csv");

/// A single tower record from the OpenCellID export.
#[derive(Debug, Clone, PartialEq)]
pub struct Tower {
    pub radio: String,
    pub lat: f64,
    pub lon: f64,
    /// OpenCellID's estimated coverage radius, in meters. This is often a
    /// rough estimate derived from sparse crowdsourced samples -- treat it
    /// generously, not as a precise cell-planning figure.
    pub range_m: u32,
}

/// Looks up towers by `(PLMN, cell ID)`, where PLMN is formatted the same
/// way as [`crate::plmn::rrc_plmn_identity_to_str`] (`"MCC-MNC"`) and the
/// cell ID is the full ECI (Cell Identity) as broadcast in SIB1, matching
/// OpenCellID's `cell` column for LTE.
pub struct OpenCellIdIndex {
    towers: HashMap<(String, u32), Tower>,
}

impl OpenCellIdIndex {
    fn parse(csv: &str) -> Self {
        let mut towers = HashMap::new();
        for line in csv.lines().skip(1) {
            let fields: Vec<&str> = line.split(',').collect();
            let [radio, mcc, net, _area, cell, _unit, lon, lat, range, ..] = fields.as_slice()
            else {
                continue;
            };
            let (Ok(mcc), Ok(mnc), Ok(cell), Ok(lon), Ok(lat), Ok(range_m)) = (
                mcc.parse::<u16>(),
                net.parse::<u16>(),
                cell.parse::<u32>(),
                lon.parse::<f64>(),
                lat.parse::<f64>(),
                range.parse::<u32>(),
            ) else {
                continue;
            };
            towers.insert(
                (format!("{mcc}-{mnc}"), cell),
                Tower {
                    radio: radio.to_string(),
                    lat,
                    lon,
                    range_m,
                },
            );
        }
        Self { towers }
    }

    pub fn lookup(&self, plmn: &str, cell_id: u32) -> Option<&Tower> {
        self.towers.get(&(plmn.to_string(), cell_id))
    }

    pub fn len(&self) -> usize {
        self.towers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.towers.is_empty()
    }
}

/// Parsed once, on first use, and shared for the life of the process.
pub static INDEX: LazyLock<OpenCellIdIndex> = LazyLock::new(|| OpenCellIdIndex::parse(CSV_DATA));

/// Great-circle distance between two lat/lon points, in meters.
pub fn distance_meters(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const EARTH_RADIUS_M: f64 = 6_371_000.0;
    let (lat1r, lat2r) = (lat1.to_radians(), lat2.to_radians());
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();
    let a = (dlat / 2.0).sin().powi(2) + lat1r.cos() * lat2r.cos() * (dlon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
    EARTH_RADIUS_M * c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_bundled_csv() {
        // Sanity check against the real data rather than a synthetic
        // fixture, so a bad re-export of the CSV fails this test.
        assert!(INDEX.len() > 1000, "expected a substantial tower index");
    }

    #[test]
    fn looks_up_a_known_row() {
        // First data row of middle_tn_towers.csv:
        // LTE,310,410,8840,41733647,0,-86.7354,36.2672,8495,35,1,...
        let tower = INDEX.lookup("310-410", 41733647).expect("row should exist");
        assert_eq!(tower.radio, "LTE");
        assert_eq!(tower.lat, 36.2672);
        assert_eq!(tower.lon, -86.7354);
        assert_eq!(tower.range_m, 8495);
    }

    #[test]
    fn missing_cell_is_none() {
        assert!(INDEX.lookup("310-410", u32::MAX).is_none());
        assert!(INDEX.lookup("999-999", 1).is_none());
    }

    #[test]
    fn distance_of_a_point_from_itself_is_zero() {
        assert_eq!(distance_meters(36.2672, -86.7354, 36.2672, -86.7354), 0.0);
    }

    #[test]
    fn distance_matches_a_known_reference() {
        // One degree of longitude at the equator is ~111.32 km.
        let d = distance_meters(0.0, 0.0, 0.0, 1.0);
        assert!((d - 111_320.0).abs() < 500.0, "got {d}m");
    }
}
