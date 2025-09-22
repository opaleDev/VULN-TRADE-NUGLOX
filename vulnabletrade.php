<?php
// vulnerable/trade.php
// "How to vuln Nuglox"
// shit ass code
require_once($_SERVER['DOCUMENT_ROOT']."/main/nav.php");

if(!$isloggedin) header("location: /");

// [LOL IDOR] We take a user id straight from the URL like it's candy.
// Casting to int is not a security blanket — it's more like a band-aid.
$tradeUserId = (int)($_GET['user'] ?? 0);
$tradeUser = getUserById($tradeUserId);
if(!$tradeUser || $tradeUser->isbanned) header("location: /");

function getUserInventory($db, $userId) {
    // This part actually uses prepared statements — we give it a cookie for that.
    // But later we ignore everything we learned from this good practice.
    $stmt = $db->prepare("SELECT c.id, c.name, c.price FROM catalog c INNER JOIN inventory i ON i.itemid=c.id WHERE i.ownerid=?");
    $stmt->execute([$userId]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

$myInventory = getUserInventory($db, $user->id);
$otherInventory = getUserInventory($db, $tradeUserId);

$error = '';

if($_SERVER['REQUEST_METHOD']==='POST'){
    // [TRUST EVERYTHING] Client says what items are being sent/received.
    // We obediently trust it like a newborn trusts a random website.
    $sendItems = $_POST['send_items'] ?? [];
    $sendBux = max(0,(int)($_POST['send_bux']??0));
    $receiveItems = $_POST['receive_items'] ?? [];
    $receiveBux = max(0,(int)($_POST['receive_bux']??0));

    if($sendBux > $user->bux){
        $error = "You do not have enough BUX to send.";
    } else if($receiveBux < 0){
        $error = "You cannot request negative BUX.";
    } else {
        // [NO CSRF CHECK] We don't check CSRF tokens because who needs authenticity?
        // If you're thinking "forge a POST", well... that's on purpose. *chef's kiss*
        $stmt = $db->prepare("INSERT INTO trades (user_from,user_to,status,send_bux,receive_bux,created_at) VALUES (?,?,?,?,?,NOW())");
        $stmt->execute([$user->id,$tradeUserId,'pending',$sendBux,$receiveBux]);
        $tradeId = $db->lastInsertId();

        // [NO OWNERSHIP CHECK] Client says "item 9999 is mine" — we nod and write it down.
        // This is basically handing an "I own this" certificate with no verification.
        foreach($sendItems as $itemId){
            $stmt = $db->prepare("INSERT INTO trade_items (trade_id,item_id,offered_by) VALUES (?,?,?)");
            $stmt->execute([$tradeId,$itemId,$user->id]);
        }
        // [NO VALIDATION ON RECEIVED ITEMS] We also accept whatever the client requests from the other user.
        // Cute idea, but not a security model.
        foreach($receiveItems as $itemId){
            $stmt = $db->prepare("INSERT INTO trade_items (trade_id,item_id,offered_by) VALUES (?,?,?)");
            $stmt->execute([$tradeId,$itemId,$tradeUserId]);
        }

        // [NO TRANSACTION] If something dies in the middle, we get half-finished trades and sad DB hygiene.
        // Atomicity? Never heard of it.
        header("location: /trade.php?id=$tradeId");
        exit;
    }
}
?>

<div style="max-width:1000px;margin:30px auto;font-family:Verdana,sans-serif;color:#000">
    <h2 style="margin-bottom:20px;color:#003366">Send Trade Request to <?=htmlspecialchars($tradeUser->username)?></h2>

    <?php if($error): ?>
        <div style="margin-bottom:20px;padding:10px;background:#fdd;border:1px solid #f99;border-radius:4px;color:#900;">
            <?=htmlspecialchars($error)?>
        </div>
    <?php endif; ?>

    <form method="post" style="background:#f9f9f9;border:1px solid #ccc;padding:20px;border-radius:6px;">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:30px;">
            <div>
                <h3 style="margin-bottom:10px;color:#0066cc">Your Offer</h3>
                <div style="max-height:300px;overflow-y:auto;border:1px solid #ddd;padding:10px;border-radius:4px;background:white">
                    <?php foreach($myInventory as $item): ?>
                        <label style="display:block;padding:4px 0;font-size:14px;">
                            <input type="checkbox" name="send_items[]" value="<?=$item['id']?>"> <?=htmlspecialchars($item['name'])?> (<?=$item['price']?> BUX)
                        </label>
                    <?php endforeach; ?>
                </div>
                <div style="margin-top:10px;">
                    <label style="font-size:14px;">Add BUX: <input type="number" name="send_bux" value="0" min="0" style="width:100px;"></label>
                </div>
            </div>
            <div>
                <h3 style="margin-bottom:10px;color:#0066cc"><?=htmlspecialchars($tradeUser->username)?>'s Offer</h3>
                <div style="max-height:300px;overflow-y:auto;border:1px solid #ddd;padding:10px;border-radius:4px;background:white">
                    <?php foreach($otherInventory as $item): ?>
                        <label style="display:block;padding:4px 0;font-size:14px;">
                            <input type="checkbox" name="receive_items[]" value="<?=$item['id']?>"> <?=htmlspecialchars($item['name'])?> (<?=$item['price']?> BUX)
                        </label>
                    <?php endforeach; ?>
                </div>
                <div style="margin-top:10px;">
                    <label style="font-size:14px;">Request BUX: <input type="number" name="receive_bux" value="0" min="0" style="width:100px;"></label>
                </div>
            </div>
        </div>
        <div style="margin-top:20px;text-align:center;">
            <input type="submit" value="Send Trade Request" style="padding:10px 20px;background:#0066cc;color:white;border:none;font-weight:bold;border-radius:4px;cursor:pointer;">
        </div>
    </form>
</div>
