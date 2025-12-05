<?php
session_start();

/* ---- helpers ---- */
function rand_hex($bytes = 16) {
    if (function_exists('random_bytes')) return bin2hex(random_bytes($bytes));
    if (function_exists('openssl_random_pseudo_bytes')) return bin2hex(openssl_random_pseudo_bytes($bytes));
    $out = '';
    for ($i = 0; $i < $bytes; $i++) $out .= chr(mt_rand(0,255));
    return bin2hex($out);
}
function h($s){ return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
function gv($arr,$k,$d=''){ return isset($arr[$k]) ? $arr[$k] : $d; }

/* ---- DB (SQLite) ---- */
$dbFile = __DIR__ . '/data.sqlite';
try {
    $pdo = new PDO('sqlite:'.$dbFile);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (Exception $e) {
    echo "DB error: " . h($e->getMessage());
    exit;
}

/* Ensure users table exists (fields: first,last,gender,dob,email,password) */
$pdo->exec("CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE,
  password_hash TEXT,
  first_name TEXT,
  last_name TEXT,
  gender TEXT,
  dob TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)");

/* CSRF token */
if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = rand_hex(16);

/* route and state */
$action = gv($_GET,'action','signup'); // default to signup page
$errors = [];
$info = '';

/* ---------------- SIGNUP ---------------- */
if ($action === 'signup' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf'], gv($_POST,'csrf',''))) $errors[] = 'Invalid request.';
    $first = trim(gv($_POST,'first_name',''));
    $last  = trim(gv($_POST,'last_name',''));
    $gender= trim(gv($_POST,'gender',''));
    $dob   = trim(gv($_POST,'dob',''));
    $email = trim(gv($_POST,'email',''));
    $pass  = gv($_POST,'password','');

    if ($first === '') $errors[] = 'First name required.';
    if ($last === '')  $errors[] = 'Last name required.';
    if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = 'Valid email required.';
    if (strlen($pass) < 6) $errors[] = 'Password must be at least 6 characters.';

    if (empty($errors)) {
        try {
            $hash = password_hash($pass, PASSWORD_DEFAULT);
            $st = $pdo->prepare("INSERT INTO users (email,password_hash,first_name,last_name,gender,dob) VALUES (?,?,?,?,?,?)");
            $st->execute([$email,$hash,$first,$last,$gender,$dob]);

            // regenerate CSRF and redirect to login (PRG)
            $_SESSION['csrf'] = rand_hex(16);
            header("Location: ?action=login&created=1");
            exit;
        } catch (PDOException $e) {
            if (stripos($e->getMessage(), 'unique') !== false) $errors[] = 'Email already registered.';
            else $errors[] = 'Database error.';
        }
    }
}

/* ---------------- LOGIN ---------------- */
if ($action === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf'], gv($_POST,'csrf',''))) $errors[] = 'Invalid request.';
    $email = trim(gv($_POST,'email',''));
    $pass  = gv($_POST,'password','');

    if (empty($errors)) {
        $st = $pdo->prepare("SELECT * FROM users WHERE email = ?");
        $st->execute([$email]);
        $u = $st->fetch(PDO::FETCH_ASSOC);
        if ($u && password_verify($pass, $u['password_hash'])) {
            $_SESSION['user'] = [
                'id' => $u['id'],
                'email' => $u['email'],
                'first_name' => $u['first_name'],
                'last_name' => $u['last_name']
            ];
            header("Location: ?action=home");
            exit;
        } else {
            $errors[] = 'Invalid credentials.';
        }
    }
}

/* ---------------- LOGOUT ---------------- */
if ($action === 'logout') {
    session_unset();
    session_destroy();
    session_start();
    $_SESSION['csrf'] = rand_hex(16);
    header("Location: ?action=signup");
    exit;
}

/* ---------- HTML output ---------- */
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Registration</title>

<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
:root{
  --page-bg: #e9ddc7;
  --card-start: #072b2b;
  --card-end: #0b2f30;
  --accent: #23c698;
  --muted: #9fcfc6;
  --input-bg: #ffffff;
  --text-dark: #042826;
}
*{box-sizing:border-box}
html,body{height:100%;margin:0}
body{
  background:var(--page-bg);
  font-family:'Inter',system-ui,Segoe UI,Roboto,Arial;
  display:flex;
  align-items:center;
  justify-content:center;
  padding:40px;
}

/* Card */
.container{
  width:100%;
  max-width:780px;
  padding:28px;
}
.card{
  background: linear-gradient(180deg,var(--card-start),var(--card-end));
  border-radius:18px;
  padding:32px;
  color:#e8fff7;
  box-shadow: 0 18px 50px rgba(10,10,10,0.35);
  position:relative;
}

/* Title */
.header{
  text-align:center;
  margin-bottom:18px;
}
.header h1{
  margin:0;
  font-size:36px;
  color:#aef7ea;
  letter-spacing:0.5px;
}
.header p{ margin:8px 0 0; color:var(--muted); }

/* form area */
.panel{
  background: rgba(255,255,255,0.02);
  border-radius:12px;
  padding:20px;
}

/* grid for inputs */
.grid{
  display:grid;
  grid-template-columns: 1fr 1fr;
  gap:16px 20px;
  align-items:start;
}

/* full width row */
.full { grid-column: 1 / -1; }

label{
  display:block;
  font-weight:600;
  color:#dffef3;
  margin-bottom:8px;
  font-size:14px;
}

/* inputs */
input[type="text"], input[type="email"], input[type="password"], input[type="date"], select{
  width:100%;
  padding:12px 14px;
  border-radius:12px;
  border:0;
  background:var(--input-bg);
  color:var(--text-dark);
  font-size:15px;
  box-shadow: 0 3px 0 rgba(0,0,0,0.03) inset;
  outline:none;
}

/* password eye position */
.input-wrap{ position:relative; }
.pw-toggle{
  position:absolute;
  right:12px; top:50%;
  transform:translateY(-50%);
  background:transparent;border:0; cursor:pointer; font-size:16px;
}

/* primary button */
.btn{
  display:inline-block;
  width:100%;
  padding:14px 18px;
  border-radius:12px;
  border:0;
  background: linear-gradient(180deg,var(--accent), #149573);
  color:#042826;
  font-weight:700;
  font-size:16px;
  cursor:pointer;
  box-shadow: 0 10px 22px rgba(20,120,100,0.12);
  transition: transform .08s ease;
}
.btn:active{ transform: translateY(1px); }

/* helper texts */
.row-center{ display:flex; justify-content:center; }
.note{ color:#cfeee7; text-align:center; margin-top:14px; }
.note a{ color:#dffef3; text-decoration:underline; }

/* messages */
.msg{ background:#ffecec; color:#7a1a1a; padding:10px; border-radius:8px; margin-bottom:12px; }
.info{ background:#e6ffee; color:#0b6a3c; padding:10px; border-radius:8px; margin-bottom:12px; }

/* responsive */
@media (max-width:760px){
  .grid{ grid-template-columns: 1fr; }
  .card{ padding:20px; }
  .header h1{ font-size:28px; }
}
</style>
</head>
<body>
  <div class="container">
    <div class="card">
      <div class="header">
        <h1>Registration</h1>
        <p>Create account / login</p>
      </div>

      <div class="panel">
        <?php if ($action === 'signup'): ?>

          <?php if (!empty($errors)): ?><div class="msg"><?php foreach($errors as $e) echo h($e)."<br>"; ?></div><?php endif; ?>

          <form method="post" action="?action=signup" novalidate>
            <input type="hidden" name="csrf" value="<?=h($_SESSION['csrf'])?>">
            <div class="grid">
              <div>
                <label for="first_name">First name</label>
                <input id="first_name" name="first_name" type="text" value="<?=h(gv($_POST,'first_name',''))?>" autocomplete="given-name">
              </div>

              <div>
                <label for="last_name">Last name</label>
                <input id="last_name" name="last_name" type="text" value="<?=h(gv($_POST,'last_name',''))?>" autocomplete="family-name">
              </div>

              <div>
                <label for="gender">Gender</label>
                <select id="gender" name="gender">
                  <option value="" <?= gv($_POST,'gender','')==='' ? 'selected' : '' ?>>--</option>
                  <option value="Male" <?= gv($_POST,'gender','')==='Male' ? 'selected' : '' ?>>Male</option>
                  <option value="Female" <?= gv($_POST,'gender','')==='Female' ? 'selected' : '' ?>>Female</option>
                  <option value="Other" <?= gv($_POST,'gender','')==='Other' ? 'selected' : '' ?>>Other</option>
                </select>
              </div>

              <div>
                <label for="dob">Date of birth</label>
                <input id="dob" name="dob" type="date" value="<?=h(gv($_POST,'dob',''))?>">
              </div>

              <div class="full">
                <label for="email">Email</label>
                <input id="email" name="email" type="email" value="<?=h(gv($_POST,'email',''))?>" autocomplete="email">
              </div>

              <div class="full input-wrap">
                <label for="password">Password (min 6 chars)</label>
                <input id="password" name="password" type="password" autocomplete="new-password">
                <button type="button" class="pw-toggle" aria-label="toggle password">👁</button>
              </div>
            </div>

            <div style="margin-top:18px;">
              <button class="btn" type="submit">Create Account</button>
            </div>
          </form>

          <div class="note">Already have an account? <a href="?action=login">Login</a></div>

        <?php elseif ($action === 'login'): ?>

          <?php if (isset($_GET['created'])): ?><div class="info">Account created. Please login.</div><?php endif; ?>
          <?php if (!empty($errors)): ?><div class="msg"><?php foreach($errors as $e) echo h($e)."<br>"; ?></div><?php endif; ?>

          <form method="post" action="?action=login" novalidate>
            <input type="hidden" name="csrf" value="<?=h($_SESSION['csrf'])?>">
            <div class="grid">
              <div class="full">
                <label for="email_login">Email</label>
                <input id="email_login" name="email" type="email" value="<?=h(gv($_POST,'email',''))?>" autocomplete="email">
              </div>

              <div class="full input-wrap">
                <label for="password_login">Password</label>
                <input id="password_login" name="password" type="password" autocomplete="current-password">
                <button type="button" class="pw-toggle" aria-label="toggle password">👁</button>
              </div>
            </div>

            <div style="margin-top:18px;">
              <button class="btn" type="submit">Login</button>
            </div>
          </form>

          <div class="note">Don't have an account? <a href="?action=signup">Create</a></div>

        <?php elseif ($action === 'home' && isset($_SESSION['user'])): ?>

          <div class="info">Successfully logged in.</div>

          <div style="margin-bottom:14px">
            <div style="font-weight:700; font-size:18px; color:#dffef3;"><?= h($_SESSION['user']['first_name'] . ' ' . $_SESSION['user']['last_name']) ?></div>
            <div style="color:var(--muted)"><?= h($_SESSION['user']['email']) ?></div>
          </div>

          <div class="row-center">
            <form method="get" action="?action=logout" style="width:100%;">
              <button class="btn" type="submit" style="background:#ff6b6b">Logout</button>
            </form>
          </div>

        <?php else: ?>
          <div style="text-align:center; color:var(--muted)">
            <a href="?action=signup" style="color:#dffef3; text-decoration:underline">Create account</a> or
            <a href="?action=login" style="color:#dffef3; text-decoration:underline">Login</a>
          </div>
        <?php endif; ?>
      </div>
    </div>
  </div>

<script>
/* password eye toggle for any password inputs in the panel */
document.querySelectorAll('.pw-toggle').forEach(function(btn){
  btn.addEventListener('click', function(e){
    var wrap = btn.closest('.input-wrap');
    if (!wrap) return;
    var inp = wrap.querySelector('input[type="password"], input[type="text"]');
    if (!inp) return;
    if (inp.type === 'password'){ inp.type = 'text'; btn.textContent = '🙈'; }
    else { inp.type = 'password'; btn.textContent = '👁'; }
    inp.focus();
  });
});
</script>
</body>
</html>
