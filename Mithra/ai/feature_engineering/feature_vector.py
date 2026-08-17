from dataclasses import dataclass


@dataclass
class FeatureVector:

    permission_count: int = 0

    suspicious_permission_count: int = 0

    activity_count: int = 0

    service_count: int = 0

    receiver_count: int = 0

    provider_count: int = 0

    total_classes: int = 0

    total_methods: int = 0

    network_api_count: int = 0

    crypto_api_count: int = 0

    reflection_api_count: int = 0

    runtime_api_count: int = 0

    dynamic_loading_count: int = 0

    file_api_count: int = 0

    url_count: int = 0

    ip_count: int = 0

    domain_count: int = 0