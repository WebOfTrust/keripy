

MultiHab can consist of the following:
 - 1 or more local AIDs, 1 or more remote AIDs: GroupHab
 - 1 or more Signify Clients, 0 or more remote AIDs: SignifyHab

The key to implementing them all is allowing the had to incept, rotate and interact by accepting
the Serder of the event and the signatures.

Helper methods are need to create the (icp, rot, ixn) events given the Verfers, Digers and all other parameters.

Helper methods are needed to parse the event.

Helper method needed to extract Merfers / Digers from smids and rmids

Signing the event only occurs when there are 1 or more local AIDs so we have to account for that in the larger group logic.  So when event
creation occurs, IF THERE ARE ANY LOCAL AIDs, THEY MUST ALSO SIGN THE EVENT

When you create a MultiHab you must be able to specify the consituents:

What if this was a Hab that just knows about verfers, merfers for inception and rotation to create the events.

Then a method to parse the event that will, before parsing, sign the event with any local AIDs that are present.

createEvent(merger, diger) -

parseEvent(serder, sigers) -> signs with local Habs if there

updateHabRecord()...

Allow for creation of the event by the lead that is either local or Signify client or other multisig AID

Start with SkelHab for just parse and sign event.

