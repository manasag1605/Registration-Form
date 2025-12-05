<?php
// Connect to the same SQLite DB used by your application
$db = new PDO('sqlite:' . __DIR__ . '/data.sqlite');

// Retrieve all registered users
$users = $db->query("
    SELECT id, first_name, last_name, email, gender, dob, created_at
    FROM users
    ORDER BY id DESC
")->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html>
<head>
<title>Registered Users</title>
<style>
body {
    font-family: Arial, sans-serif;
    padding: 20px;
    background: #f4f4f4;
}
h2 {
    margin-bottom: 15px;
}
table {
    border-collapse: collapse;
    width: 100%;
    background: white;
}
th, td {
    padding: 10px;
    border: 1px solid #ccc;
    text-align: left;
}
th {
    background: #eaeaea;
}
</style>
</head>
<body>

<h2>Registered Users</h2>

<table>
<tr>
  <th>ID</th>
  <th>Name</th>
  <th>Email</th>
  <th>Gender</th>
  <th>Date of Birth</th>
  <th>Registered At</th>
</tr>

<?php foreach ($users as $u): ?>
<tr>
  <td><?= $u['id'] ?></td>
  <td><?= htmlspecialchars($u['first_name'] . " " . $u['last_name']) ?></td>
  <td><?= htmlspecialchars($u['email']) ?></td>
  <td><?= htmlspecialchars($u['gender']) ?></td>
  <td><?= htmlspecialchars($u['dob']) ?></td>
  <td><?= htmlspecialchars($u['created_at']) ?></td>
</tr>
<?php endforeach; ?>

</table>

</body>
</html>
