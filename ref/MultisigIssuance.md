
Multisig rotation must be extracted into a method outside of the Doer
* This methods takes care of publishing the mid rotation event.
* Or should the method return the mid rotation appended to the bytes?  That way the multisig Doer can just witness them
  and the caller of Issue can deal with them.  Caller won't care how many there are
* No rotation parameters should be changed on the multisig identifier during a multisig rotation


Multisig interaction (signing) must also be a method

Modify Issuer.anchorMsg to call the multisig-enabled methods if appropriate

Issue credential endpoint handler must decide if its a multisig agent and send out `exn` messages to other
participant(s) to let them know a credential must be signed.  Token ring propagation or gossip protocol between
participants.

How does ((2/3), (6/7)) propagation work so only the top three _need_ to participate?

Initiator of protocol event should be responsible for gathering receipts and submitting final event when enough
receipts have been received.  Its exactly the same as gathering receipts from witnesses.

Once threshold is reached, the credential can be sent to Holder and the events submitted to witnesses.

Update multisig inception/rotation to follow the same procedure.  The initiator of the inception/rotation is
responsible for gathering all reciepts and propagating them, not the "first guy in the list"

Credential Issuance needs an escrow.  And the receipts are processed against that escrow as they are received and
when the credential meets its threshold, It is taken out of escrow and sent to the holder and the events sent to the
witnesses.  This way, the other participants are just receipting the credential, not worrying about processing it
themselves.  They just need to also pull the KEL and TEL events from witnesses when they are done.

Do we need to propagate the Credentials to all participants?  Or can the originator of the credential be enough to
hold on to it

Coming out of Escrow signals initiator to send events to Witnesses and other participants and Credential to Holder!!!!!
