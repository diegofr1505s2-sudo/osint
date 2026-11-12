from catexe.modules.geolocation import GeoHypothesis, confidence_text, limitation_text, rank_hypotheses
from catexe.modules.ip_attribution import summarize_ip_sources


def test_geo_hypotheses_rank_without_claiming_exactness():
    items = [
        GeoHypothesis(50.8, 4.3, "Bruxelles", 0.22, source="geoclip", radius_km=150),
        GeoHypothesis(48.8, 2.3, "Paris", 0.52, source="geoclip", radius_km=150),
    ]
    ranked = rank_hypotheses(items)
    assert ranked[0].label == "Paris"
    assert confidence_text(ranked[0]) == "faible"
    assert "non confirmée" in limitation_text(ranked[0])


def test_exif_has_higher_confidence_than_model_estimate():
    exif = GeoHypothesis(48.8, 2.3, "GPS EXIF", source="exif")
    assert exif.confidence == "high"


def test_ip_summary_reports_source_agreement_and_network_limit():
    summary = summarize_ip_sources(
        {"country": "France", "city": "Paris", "connection": {"isp": "Example ISP"}},
        {"country": "France", "city": "Lyon", "isp": "Example ISP"},
    )
    assert summary.country == "France"
    assert summary.agreement == 1
    assert summary.precision == "ville estimée"
    assert "personne" in summary.warning
