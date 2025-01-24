import falcon
from .. import help
from ..db import dbing
from ..vdr import viring

logger = help.ogler.getLogger()

class QueryEnd:
    """ Endpoint class for quering witness for KELs and TELs using HTTP GET

     """

    def __init__(self, hab):
        self.hab = hab
        self.reger = viring.Reger(name=hab.name, db=hab.db, temp=False)

    def on_get(self, req, rep):
        """ Handles GET requests to query KEL or TEL events of a pre from a witness.

            Parameters:
                req (Request) Falcon HTTP request
                rep (Response) Falcon HTTP response

            Query Parameters:
                typ (string): The type of event data to query for. Accepted values are:
                    - 'kel': Retrieve KEL events for a specified 'pre'.
                    - 'tel': Retrieve TEL events  based on 'reg' or 'vcid'.
                pre (string, optional): For 'kel' queries, the specific 'pre' to query.
                sn (int, optional): For "kel" queries. If provided, returns events with seq-num
                                   greater than or equal to `sn`.
                reg (string, optional): For 'tel' queries, registry pre. required if `vcid` is not provided.
                vcid (string, optional): For 'tel' queries, credential said. required if `reg` is not provided.

            Response:
                - 200 OK: Returns event data in "application/json+cesr" format.
                - 400 Bad Request: Returned if required query parameters are missing or if an invalid `typ` is specified.

            Example:
                - /query?typ=kel&pre=ELZ1KBCFOmdj1RPu6kMUnzgMBTl4YsHfpw7wIGvLgW5W
                - /query?typ=kel&pre=ELZ1KBCFOmdj1RPu6kMUnzgMBTl4YsHfpw7wIGvLgW5W&sn=5
                - /query?typ=tel&reg=EHrbPfpRLU9wpFXTzGY-LIo2FjMiljjEnt238eWHb7yZ&vcid=EO5y0jMXS5XKTYBKjCUPmNKPr1FWcWhtKwB2Go2ozvr0

        """

        typ = req.get_param("typ")

        if not typ:
            raise falcon.HTTPBadRequest(description="'typ' query param is required")

        if typ == "kel":
            pre = req.get_param("pre")

            if not pre:
                raise falcon.HTTPBadRequest(description="'pre' query param is required")

            evnts = bytearray()

            sn = req.get_param_as_int("sn")
            if sn is not None: ## query for event with seq-num >= sn
                preb = pre.encode("utf-8")
                dig = self.hab.db.getKeLast(key=dbing.snKey(pre=preb,
                                                            sn=sn))
                if dig is None:
                    raise falcon.HTTPBadRequest(description=f"non-existant event at seq-num {sn}")

                for dig in self.hab.db.getKelIter(pre, sn=sn):
                    try:
                        msg = self.hab.db.cloneEvtMsg(pre=pre, fn=0, dig=dig)
                    except Exception:
                        continue  # skip this event
                    evnts.extend(msg)
            else:
                for msg in self.hab.db.clonePreIter(pre=pre):
                    evnts.extend(msg)


            rep.set_header('Content-Type', "application/json+cesr")
            rep.status = falcon.HTTP_200
            rep.data = bytes(evnts)

        elif typ == "tel":
            regk = req.get_param("reg")
            vcid = req.get_param("vcid")

            if not regk and not vcid:
                raise falcon.HTTPBadRequest(description="Either 'reg' or 'vcid' query param is required for TEL query")

            evnts = bytearray()
            if regk is not None:
                cloner = self.reger.clonePreIter(pre=regk)
                for msg in cloner:
                    evnts.extend(msg)

            if vcid is not None:
                cloner = self.reger.clonePreIter(pre=vcid)
                for msg in cloner:
                    evnts.extend(msg)

            rep.set_header('Content-Type', "application/json+cesr")
            rep.status = falcon.HTTP_200
            rep.data = bytes(evnts)

        else:
            rep.set_header('Content-Type', "application/json")
            rep.text = "unkown query type."
            rep.status = falcon.HTTP_400
