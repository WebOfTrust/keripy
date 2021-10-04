from dataclasses import dataclass


@dataclass
class Location:
    ip4: str
    tcp: int
    http: int = 0


witnesses = {
    "B8NkPDTGELcUDH-TBCEjo4dpCvUnO_DnOSNEaNlL--4M": Location(ip4="127.0.0.1", tcp=5631),
    "BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo": Location(ip4="127.0.0.1", tcp=5632, http=5642),  # wan
    "BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw": Location(ip4="127.0.0.1", tcp=5633, http=5643),  # wil
    "Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c": Location(ip4="127.0.0.1", tcp=5634, http=5644),  # wes
    "BQv9IGwE8qd6GWtb_edv8kY5MpXKgCZHQYByqp0by0d4": Location(ip4="127.0.0.1", tcp=5652, http=5651),  # watcher
    "Eu_se69BU6tYdF2o-YD411OzwbvImOfu1m023Bu8FM_I": Location(ip4="127.0.0.1", tcp=5621, http=5620),
    "EEWuHgyO9iTgfz43mtY1IaRH-TrmV-YpcbpPoKKSpz8U": Location(ip4="127.0.0.1", tcp=5721, http=5720),
    "E5JuUB6iOaKV5-0EeADj0S3KCvvkUZDnuLw8VPK8Qang": Location(ip4="127.0.0.1", tcp=5821, http=5820),

    # "BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo": Location(ip4="52.188.131.0", tcp=5632, http=5642),  # wan
    # "BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw": Location(ip4="52.186.43.227", tcp=5633, http=5643),  # wil
    # "Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c": Location(ip4="52.186.44.60", tcp=5634, http=5644),  # wes
}


def getwitnessbyprefix(qb64):
    """
    Resolve witness information (IP address) for the given identifier

    Parameters
       qb64 (str): qb64 identifier prefix of the witness to resolve

    Returns:
        Location object with endpoint information

    """

    if qb64 not in witnesses:
        return None

    d = witnesses[qb64]
    return d


endpoints = {
    "EhYpYZSUAtiEurF7XngDB2mII2khY9ktlfqKHd1NHfNY": Location(ip4="127.0.0.1", tcp=5629, http=0),  # Demo HAN
    "ExwBAYqvPpaPpGmBCixIiC_xpcDto8YUxLoNJgE2FOKo": Location(ip4="127.0.0.1", tcp=5621, http=5620),  # GLEIF Agent
}


def getendpointbyprefix(qb64):
    """
    Resolve controller location information (IP address) for the given identifier

    Parameters
       qb64 (str): qb64 identifier prefix of the controller to resolve

    Returns:
        Location object with endpoint information

    """

    if qb64 not in endpoints:
        return None

    d = endpoints[qb64]
    return d


witness_resolver = {
    "EeS834LMlGVEOGR8WU3rzZ9M6HUv_vtF32pSXQXKP7jg": ["BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo",
                                                     "BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw",
                                                     "Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"],
    "EZNNZO-Sa41t-ps_jwOeeDmo2x_nPNavwOEl1QbN7O7s": ["BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo",
                                                     "BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw",
                                                     "Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"]
}


def getwitnessesforprefix(qb64):
    return witness_resolver[qb64]
