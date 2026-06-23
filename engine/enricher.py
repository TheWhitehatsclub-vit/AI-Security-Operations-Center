import os
import logging
from pathlib import Path
from config.settings import GEOIP_DB_PATH, GEOIP_ASN_PATH

log = logging.getLogger(__name__)

class GeoEnricher:
    def __init__(self):
        self._city_reader = None
        self._asn_reader = None
        self._load_databases()

    def _load_databases(self):
        try:
            import maxminddb
            city_path = Path(GEOIP_DB_PATH)
            asn_path = Path(GEOIP_ASN_PATH)
            if city_path.exists():
                self._city_reader = maxminddb.open_database(str(city_path), maxminddb.MODE_AUTO)
                log.info(f"GeoIP City DB loaded: {city_path}")
            else:
                log.warning(f"GeoIP City DB not found at {city_path}. Run: python scripts/download_geoip.py")
            if asn_path.exists():
                self._asn_reader = maxminddb.open_database(str(asn_path), maxminddb.MODE_AUTO)
                log.info(f"GeoIP ASN DB loaded: {asn_path}")
            else:
                log.warning(f"GeoIP ASN DB not found at {asn_path}")
        except ImportError:
            log.warning("maxminddb not installed. GeoIP disabled. pip install maxminddb")

    def enrich(self, log_norm: dict) -> dict:
        ip = log_norm["flat"].get("source_ip", log_norm["flat"].get("src_ip", ""))
        if not ip or ip == "unknown" or ip.startswith(("10.", "172.", "192.168.", "127.", "169.", "0.")):
            log_norm["geo"] = {"country": "", "city": "", "asn": "", "isp": "", "is_private": True}
            return log_norm

        geo = {"country": "", "city": "", "asn": "", "isp": "", "is_private": False}

        if self._city_reader:
            try:
                city_data = self._city_reader.get(ip)
                if city_data:
                    geo["country"] = (
                        city_data.get("country", {}).get("iso_code", "")
                        or city_data.get("registered_country", {}).get("iso_code", "")
                    )
                    geo["city"] = city_data.get("city", {}).get("names", {}).get("en", "")
                    subdivisions = city_data.get("subdivisions", [])
                    if subdivisions:
                        geo["region"] = subdivisions[0].get("names", {}).get("en", "")
                    geo["location"] = city_data.get("location", {})
                    geo["continent"] = city_data.get("continent", {}).get("code", "")
            except Exception:
                pass

        if self._asn_reader:
            try:
                asn_data = self._asn_reader.get(ip)
                if asn_data:
                    geo["asn"] = str(asn_data.get("autonomous_system_number", ""))
                    geo["isp"] = asn_data.get("autonomous_system_organization", "")
            except Exception:
                pass

        log_norm["geo"] = geo
        log_norm["fields"]["geo_country"] = geo["country"]
        log_norm["fields"]["geo_city"] = geo["city"]
        log_norm["fields"]["geo_asn"] = geo["asn"]
        log_norm["fields"]["geo_isp"] = geo["isp"]
        log_norm["flat"]["geo_country"] = geo["country"]
        log_norm["flat"]["geo_city"] = geo["city"]
        log_norm["flat"]["geo_asn"] = geo["asn"]
        log_norm["flat"]["geo_isp"] = geo["isp"]

        return log_norm

    def close(self):
        if self._city_reader:
            self._city_reader.close()
        if self._asn_reader:
            self._asn_reader.close()

_enricher = None

def get_enricher():
    global _enricher
    if _enricher is None:
        _enricher = GeoEnricher()
    return _enricher
