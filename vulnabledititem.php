<?php
// vulnerable/edit_item.php
// FUCK
// WARNING: THIS BELONGS TO EPIK17 ONLY.

require_once 'main/nav.php';

// [LOGIN ONLY] We check login, but there’s no CSRF protection at all.
// Any malicious site can trick logged-in users into submitting edits.
if(!$isloggedin){
    header("Location: /");
    exit;
}

$id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
// [WEAK OWNER CHECK] We only check creatorid = current user.
// But what about admins, group-owned items, or shared ownership? Nope.
$stmt = $db->prepare("SELECT * FROM catalog WHERE id=? AND creatorid=?");
$stmt->execute([$id, $user->id]);
if ($stmt->rowCount() < 1) {
    header("Location: /catalog.php");
    exit;
}
$item = $stmt->fetch();

$msg_script = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // [NO LENGTH VALIDATION] We trim but don’t check real lengths except for name maxlength in HTML.
    // Description could be arbitrarily long, stored in DB without limits until it blows up.
    $name = trim($_POST['name'] ?? '');
    $description = trim($_POST['description'] ?? '');
    $price = (int)($_POST['price'] ?? 0);

    if ($name === '' || $price < 0) {
        // [JAVASCRIPT INJECTION OPPORTUNITY] We drop raw strings into JS without escaping.
        // Luckily here only static messages, but still: mixing PHP+JS = fertile ground for XSS mistakes.
        $msg_script = "NUGLOXLoading.show('Invalid input', '/images/error.png'); setTimeout(()=>NUGLOXLoading.hide(),2000);";
    } else {
        // [BLIND UPDATE] No extra checks. User can rename items repeatedly without audit logging.
        $update = $db->prepare("UPDATE catalog SET name=?, description=?, price=?, updated=NOW() WHERE id=?");
        $update->execute([$name, $description, $price, $id]);
        $msg_script = "NUGLOXLoading.show('Item updated successfully!', '/images/exclamation.png'); setTimeout(()=>NUGLOXLoading.hide(),2000);";
    }
}
?>

<div id="page" style="width:600px;margin:30px auto;font-family:Verdana,sans-serif;color:#000;">
  <h2>Edit Item: <?= htmlspecialchars($item['name']) ?></h2>
  <form method="post" id="edit-item-form">
    <label>
      Name:<br>
      <input type="text" name="name" style="width:100%;padding:6px;" maxlength="100" value="<?= htmlspecialchars($item['name']) ?>" required>
    </label><br><br>
    <label>
      Description:<br>
      <!-- [POTENTIAL XSS] Stored description is echoed back into textarea.
           We wrap it in htmlspecialchars, but if a dev forgets one day… kaboom. -->
      <textarea name="description" style="width:100%;padding:6px;" rows="5"><?= htmlspecialchars($item['description']) ?></textarea>
    </label><br><br>
    <label>
      Price:<br>
      <!-- [NO SERVER-SIDE LIMIT] User can enter crazy-high prices if they bypass min=0 in HTML. -->
      <input type="number" name="price" style="width:100%;padding:6px;" min="0" value="<?= (int)$item['price'] ?>" required> <!-- sigma. -->
    </label><br><br>
    <button type="submit" style="padding:8px 16px;background:#0066cc;color:white;border:none;font-weight:bold;cursor:pointer;">Save Changes</button> 
  </form>
</div>

<script>
<?= $msg_script ?>
</script>
