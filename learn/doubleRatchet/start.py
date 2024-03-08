import asyncio
import base64
import time
import traceback

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives._serialization import Encoding, PrivateFormat, KeySerializationEncryption, \
    NoEncryption
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey

from learn.doubleRatchet.colors import Colors
from learn.doubleRatchet.session import Session
from learn.doubleRatchet.user import User, PublicUser

async def loop(session: Session) -> bool:
    message = input(session.user.name + "> ")

    if message == "q":
        return False

    if message != "":
        await session.sendMessage(message)

    for message, additionalInfo in await session.readMessages():
        print(f"{session.other.name}> {Colors.OKGREEN}{message}{Colors.ENDC}")
        for header, msg in additionalInfo:
            print(f"{Colors.WARNING}{header}: {msg}{Colors.ENDC}")

    return True


async def main_loop(user: User, other: PublicUser) -> None:
    session = Session(user, other)

    print("q: Quit")

    while True:
        try:
            if not await loop(session):
                break
        except BaseException:
            print("Exception raised while processing:")
            traceback.print_exc()
            time.sleep(0.5)


async def main() -> None:
    # encryption = (
    #     PrivateFormat.Raw.encryption_builder()
    # )
    # encryption = NoEncryption()
    # x = X448PrivateKey.generate()
    # ed = Ed448PrivateKey.generate()
    # print(base64.b64encode(x.private_bytes_raw()), len(x.private_bytes_raw()))
    # print(base64.b64encode(x.public_key().public_bytes_raw()), len(x.public_key().public_bytes_raw()))
    # print(base64.b64encode(ed.private_bytes_raw()), len(ed.private_bytes_raw()))
    # print(base64.b64encode(ed.public_key().public_bytes_raw()), len(ed.public_key().public_bytes_raw()))
    # edKeyPriv = Ed448PrivateKey.from_private_bytes(x.private_bytes_raw() + b"=")
    # sig = edKeyPriv.sign(b"test")
    #
    # xPub = x.public_key()
    # edPub = Ed448PublicKey.from_public_bytes(xPub.public_bytes_raw() + b"=")
    #
    # edPub.verify(sig, b"test")
    # print(x.private_bytes(Encoding.PEM, PrivateFormat.Raw, encryption))
    # # print(x.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, encryption))
    # print(x.private_bytes(Encoding.DER, PrivateFormat.Raw, encryption))
    #
    # print(ed.private_bytes(Encoding.PEM, PrivateFormat.Raw, encryption))
    # # print(ed.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, encryption))
    # print(ed.private_bytes(Encoding.DER, PrivateFormat.Raw, encryption))
    name = input("Your Name: ")
    user = User.create(name)
    user.register()

    otherName = input("Other Name: ")
    other = PublicUser.findRegistered(otherName)

    await main_loop(user, other)


if __name__ == "__main__":
    asyncio.run(main())
