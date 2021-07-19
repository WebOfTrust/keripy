from dataclasses import dataclass


@dataclass
class Location:
    ip4: str
    tcp: int
    http: int = 0


witnesses = {
    "B8NkPDTGELcUDH-TBCEjo4dpCvUnO_DnOSNEaNlL--4M": Location(ip4="127.0.0.1", tcp=5631),
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
