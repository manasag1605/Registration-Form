<?php
// admin.php - simple admin area to view/delete users (local dev only)
session_start();

/* ---- ADMIN CREDENTIALS (change if you want) ----
   - Username: admin
   - Password: Admin@123
   To change password, replace the hash below with password_hash('NEW', PASSWORD_DEFAULT)
*/
$ADMIN_USER = 'admin';
$ADMIN_PASS_HASH = '$2y$10$9m7ZQk7Zqz1Y6hS8fJqkBe4b4e2GvZgN3G8kRz3o1F2Jn4Qe0tY2m';
 // hash for Admin@123

/* ---- DB ---- */
$db = new PDO('sqlite:' . __DIR__ . '/data.sqlite');
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

/* helpers */
function h($s){ return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

/* CSRF */
if (empty($_SESSION['admin_csrf'])) $_SESSION['admin_csrf'] = bin2hex(random_bytes(16));

$action = isset($_GET['action']) ? $_GET['action'] : 'login';
$error = '';
$msg = '';

/* LOGIN */
if ($action === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = isset($_POST['username']) ? $_POST['username'] : '';
    $pass = isset($_POST['password']) ? $_POST['password'] : '';
    if ($user !== $ADMIN_USER || !password_verify($pass, $ADMIN_PASS_HASH)) {
        $error = 'Invalid admin credentials.';
    } else {
        $_SESSION['is_admin'] = true;
        // regenerate admin csrf
        $_SESSION['admin_csrf'] = bin2hex(random_bytes(16));
        header('Location: admin.php?action=panel'); exit;
    }
}

/* LOGOUT */
if ($action === 'logout') {
    unset($_SESSION['is_admin']);
    session_regenerate_id(true);
    $msg = 'Logged out.';
    $action = 'login';
}

/* PROTECTED ACTIONS (only if admin) */
if (isset($_SESSION['is_admin']) && $_SESSION['is_admin']) {
    // Delete single user (also deletes submissions)
    if ($action === 'delete_user' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $token = isset($_POST['csrf']) ? $_POST['csrf'] : '';
        if (!hash_equals($_SESSION['admin_csrf'],$token)) $error = 'Invalid CSRF token.';
        else {
            $uid = isset($_POST['user_id']) ? (int)$_POST['user_id'] : 0;
            if ($uid > 0) {
                try {
                    $db->beginTransaction();
                    $d1 = $db->prepare("DELETE FROM submissions WHERE user_id = ?");
                    $d1->execute([$uid]);
                    $d2 = $db->prepare("DELETE FROM users WHERE id = ?");
                    $d2->execute([$uid]);
                    $db->commit();
                    $msg = "User $uid deleted.";
                    header('Location: admin.php?action=panel&msg=' . urlencode($msg)); exit;
                } catch (Exception $e) {
                    $db->rollBack();
                    $error = 'Delete failed.';
                }
            } else $error = 'Invalid user id.';
        }
    }

    // Delete all users & submissions
    if ($action === 'delete_all' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $token = isset($_POST['csrf']) ? $_POST['csrf'] : '';
        if (!hash_equals($_SESSION['admin_csrf'],$token)) $error = 'Invalid CSRF token.';
        else {
            try {
                $db->beginTransaction();
                $db->exec("DELETE FROM submissions");
                $db->exec("DELETE FROM users");
                $db->commit();
                $msg = 'All users and submissions deleted.';
                // Also logout normal sessions by regenerating server-side session store not easily done here,
                // but at least direct admin sees the change.
                header('Location: admin.php?action=panel&msg=' . urlencode($msg)); exit;
            } catch (Exception $e) {
                $db->rollBack();
                $error = 'Delete all failed.';
            }
        }
    }
}

/* Fetch users for panel */
$users = [];
if (isset($_SESSION['is_admin']) && $_SESSION['is_admin']) {
    $users = $db->query("SELECT id, first_name, last_name, email, gender, dob, created_at FROM users ORDER BY id DESC")->fetchAll(PDO::FETCH_ASSOC);
}
?>
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Admin - Users</title>
<style>
body{font-family:Inter,Arial,Helvetica,sans-serif;background:#f4f5f6;margin:0;padding:20px}
.container{max-width:980px;margin:20px auto;background:#fff;padding:18px;border-radius:10px;box-shadow:0 6px 20px rgba(0,0,0,0.08)}
h1{margin:0 0 12px}
.form-row{margin-bottom:12px}
input[type=text], input[type=password]{padding:10px;width:100%;box-sizing:border-box}
.btn{padding:8px 12px;border:0;border-radius:6px;cursor:pointer}
.btn-primary{background:#2a9df4;color:#fff}
.btn-del{background:#e74c3c;color:#fff}
.btn-ghost{background:#f1f1f1}
table{width:100%;border-collapse:collapse;margin-top:12px}
th,td{padding:10px;border-bottom:1px solid #eee;text-align:left}
th{background:#fafafa}
.notice{padding:8px;border-radius:6px;margin-bottom:12px}
.ok{background:#e8fff0;color:#0b6a3c}
.err{background:#fff0f0;color:#8a1d1d}
.actions{display:flex;gap:8px}
</style>
</head>
<body>
<div class="container">
  <h1>Admin panel</h1>

  <?php if ($error): ?><div class="notice err"><?php echo h($error); ?></div><?php endif; ?>
  <?php if (!empty($msg)) echo '<div class="notice ok">'.h($msg).'</div>'; ?>
  <?php if (isset($_GET['msg'])) echo '<div class="notice ok">'.h($_GET['msg']).'</div>'; ?>

  <?php if (!isset($_SESSION['is_admin']) || !$_SESSION['is_admin']): ?>
    <!-- login form -->
    <form method="post" action="admin.php?action=login">
      <div class="form-row">
        <label>Username</label>
        <input type="text" name="username" value="">
      </div>
      <div class="form-row">
        <label>Password</label>
        <input type="password" name="password" value="">
      </div>
      <div class="form-row">
        <button class="btn btn-primary" type="submit">Login</button>
        <a class="btn btn-ghost" href="index.php">Back to app</a>
      </div>
      <p style="color:#666;font-size:14px">Default admin: <strong>admin</strong> / <strong>Admin@123</strong></p>
    </form>

  <?php else: ?>
    <!-- panel actions -->
    <div style="display:flex;justify-content:space-between;align-items:center">
      <div>
        <form method="post" action="admin.php?action=delete_all" onsubmit="return confirm('Delete ALL users and submissions? This cannot be undone.');" style="display:inline">
          <input type="hidden" name="csrf" value="<?php echo h($_SESSION['admin_csrf']); ?>">
          <button class="btn btn-del" type="submit">Delete ALL Users</button>
        </form>
        <a class="btn btn-ghost" href="index.php" style="margin-left:8px">Open app</a>
      </div>
      <div>
        <a class="btn btn-ghost" href="admin.php?action=logout">Logout</a>
      </div>
    </div>

    <h2 style="margin-top:16px">Registered users (<?php echo count($users); ?>)</h2>

    <?php if (empty($users)): ?>
      <p style="color:#666">No registered users.</p>
    <?php else: ?>
      <table>
        <thead><tr><th>ID</th><th>Name</th><th>Email</th><th>Gender</th><th>DOB</th><th>Joined</th><th>Actions</th></tr></thead>
        <tbody>
        <?php foreach ($users as $u): $name = trim($u['first_name'].' '.$u['last_name']); ?>
          <tr>
            <td><?php echo (int)$u['id']; ?></td>
            <td><?php echo h($name); ?></td>
            <td><?php echo h($u['email']); ?></td>
            <td><?php echo h($u['gender']); ?></td>
            <td><?php echo h($u['dob']); ?></td>
            <td><?php echo h($u['created_at']); ?></td>
            <td>
              <div class="actions">
                <form method="post" action="admin.php?action=delete_user" onsubmit="return false;" id="delf-<?php echo (int)$u['id']; ?>">
                  <input type="hidden" name="user_id" value="<?php echo (int)$u['id']; ?>">
                  <input type="hidden" name="csrf" value="<?php echo h($_SESSION['admin_csrf']); ?>">
                  <button class="btn btn-del" type="button" onclick="confirmDel(<?php echo (int)$u['id']; ?>,'<?php echo h(addslashes($name)); ?>')">Delete</button>
                </form>
              </div>
            </td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    <?php endif; ?>
  <?php endif; ?>

</div>

<script>
function confirmDel(id, name){
  if (!confirm('Delete user '+ name + ' (ID '+id+')? This removes their submissions too.')) return;
  var f = document.getElementById('delf-'+id);
  if (f) f.submit();
}
</script>
</body>
</html>
