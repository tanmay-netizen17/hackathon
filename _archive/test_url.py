import asyncio, sys
sys.path.append('backend')
from detectors.url_detector import URLDetector

async def main():
    urls = [
        "https://microsoft-login-security.com",
        "https://apple-id-verify.com/signin",
        "https://google-account-suspended.com",
        "https://microsoft.com/en-us/security",
        "https://www.amazon.in/",
        "https://support.apple.com",
        "https://amazon.login.verify-user-account.info/signin"
    ]
    det = URLDetector()
    for u in urls:
        res = await det.analyse(u)
        print(f"{u}: {res['score']}")

if __name__ == '__main__':
    asyncio.run(main())
