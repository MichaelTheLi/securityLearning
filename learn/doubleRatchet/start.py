import asyncio
import time
import traceback

from learn.doubleRatchet.session import Session
from learn.doubleRatchet.user import User, PublicUser


class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

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
    name = input("Your Name: ")
    user = User.create(name)
    user.register()

    otherName = input("Other Name: ")
    other = PublicUser.findRegistered(otherName)

    await main_loop(user, other)


if __name__ == "__main__":
    asyncio.run(main())
