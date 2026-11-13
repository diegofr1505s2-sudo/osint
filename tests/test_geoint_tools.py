import pytest

from catexe.modules.geoint.elevation import (
    ELEVATION_API,
    MAX_POINTS_PER_REQUEST,
    fetch_open_meteo_elevations,
    great_circle_profile,
)
from catexe.modules.geoint.line_of_sight import analyze_sightline
from catexe.modules.geoint.triangulation import BearingObservation, intersect_bearings


def test_great_circle_profile_includes_endpoints_and_is_bounded():
    start, end = (48.85, 2.30), (48.86, 2.31)
    points = great_circle_profile(start, end, spacing_m=200)
    assert points[0] == start
    assert points[-1] == end
    assert len(points) >= 3
    with pytest.raises(ValueError, match="limite"):
        great_circle_profile(start, (49.8, 3.2), spacing_m=10, max_points=5)


def test_great_circle_profile_handles_dateline_without_long_way_round():
    points = great_circle_profile((10.0, 179.9), (10.0, -179.9), spacing_m=5000)
    assert len(points) >= 3
    wrapped_deltas = [abs((points[i + 1][1] - points[i][1] + 180) % 360 - 180) for i in range(len(points) - 1)]
    assert max(wrapped_deltas) < 0.1


def test_open_meteo_fetch_batches_at_documented_limit_and_preserves_order():
    points = [(float(index % 80), float(index % 170)) for index in range(MAX_POINTS_PER_REQUEST + 3)]
    calls = []

    def fake_get_json(url, timeout, params):
        calls.append((url, timeout, params))
        lats = params["latitude"].split(",")
        return {"elevation": [float(lat) for lat in lats]}

    values = fetch_open_meteo_elevations(points, fake_get_json)
    assert len(calls) == 2
    assert all(call[0] == ELEVATION_API for call in calls)
    assert len(calls[0][2]["latitude"].split(",")) == MAX_POINTS_PER_REQUEST
    assert len(values) == len(points)
    assert values[:3] == [0.0, 1.0, 2.0]


def test_open_meteo_missing_altitude_is_preserved_for_unknown_result():
    points = [(48.0, 2.0), (48.001, 2.001), (48.002, 2.002)]
    elevations = fetch_open_meteo_elevations(points, lambda *a, **k: {"elevation": [20, None, 22]})
    result = analyze_sightline(points[0], points[-1], elevations)
    assert result.visible is None
    assert result.minimum_clearance_m is None


def test_sightline_clear_flat_profile_and_terrain_blockage():
    start, end = (48.0, 2.0), (48.02, 2.0)
    clear = analyze_sightline(start, end, [100, 100, 100, 100, 100], 2, 2)
    blocked = analyze_sightline(start, end, [100, 100, 180, 100, 100], 2, 2)
    assert clear.visible is True
    assert blocked.visible is False
    assert blocked.minimum_clearance_m < 0
    assert blocked.obstruction_fraction == 0.5


def test_sightline_rejects_bad_profiles_and_equal_endpoints():
    with pytest.raises(ValueError, match="au moins trois"):
        analyze_sightline((0, 0), (0, 1), [1, 2])
    with pytest.raises(ValueError, match="distinctes"):
        analyze_sightline((0, 0), (0, 0), [1, 1, 1])


def test_triangulation_recovers_intersection_from_two_forward_bearings():
    observations = [
        BearingObservation(0.01, 0.0, 180),
        BearingObservation(0.0, 0.01, 270),
    ]
    result = intersect_bearings(observations, bearing_uncertainty_deg=1)
    assert abs(result.latitude) < 1e-6
    assert abs(result.longitude) < 1e-6
    assert result.all_rays_forward
    assert result.residual_rms_m < 0.1
    assert result.uncertainty_radius_m > 0


def test_triangulation_detects_rays_pointing_away_from_estimate():
    observations = [
        BearingObservation(0.01, 0.0, 0),
        BearingObservation(0.0, 0.01, 90),
    ]
    result = intersect_bearings(observations)
    assert not result.all_rays_forward


def test_triangulation_handles_local_points_across_the_dateline():
    result = intersect_bearings([
        BearingObservation(0.01, 180.0, 180),
        BearingObservation(0.0, 179.99, 90),
    ])
    wrapped_delta = abs((result.longitude - 180 + 180) % 360 - 180)
    assert abs(result.latitude) < 1e-6
    assert wrapped_delta < 1e-6


def test_triangulation_rejects_parallel_or_insufficient_bearings():
    with pytest.raises(ValueError, match="au moins deux"):
        intersect_bearings([BearingObservation(0, 0, 0)])
    with pytest.raises(ValueError, match="parallèles|faible"):
        intersect_bearings([
            BearingObservation(0.01, 0, 180),
            BearingObservation(0, 0.01, 0),
        ])


def test_triangulation_rejects_invalid_bearing_uncertainty():
    with pytest.raises(ValueError, match="incertitude"):
        intersect_bearings([
            BearingObservation(0.01, 0, 180),
            BearingObservation(0, 0.01, 270),
        ], 0)
