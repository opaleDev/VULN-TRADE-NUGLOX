<?php
// vulnerable/wear_item.php
// "How to vuln Nuglox" 
// WARNING: this belongs to epik17.

header('Content-Type: application/json');
require_once($_SERVER['DOCUMENT_ROOT'].'/main/config.php');

// [SESSION CHECK?] We only check $isloggedin, but no CSRF tokens. 
// So any site can trick the logged-in user into POSTing here (classic CSRF).
if (!$isloggedin) {
    echo json_encode(['success' => false, 'error' => 'Not logged in']);
    exit;
}

$userId = $user->id;
// [TRUSTING CLIENT DATA] We accept "id" straight from POST. 
// There’s no ownership validation to confirm the user actually owns the item.
$itemId = (int)($_POST['id'] ?? 0);

if (!$itemId) {
    echo json_encode(['success' => false, 'error' => 'Invalid item ID']);
    exit;
}

try {
    $db->beginTransaction();

    // [SELECT *] Because we love pulling all columns, even if we only need a few.
    $stmt = $db->prepare("SELECT * FROM catalog WHERE id = ?");
    $stmt->execute([$itemId]);
    $item = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$item) {
        echo json_encode(['success' => false, 'error' => 'Item not found']);
        exit;
    }

    $itemType = strtolower($item['type']);

    if ($itemType === 'hat') {
        // [MAGIC LIMITS] We allow max 3 hats, because why not. 
        // Of course, no server-side enforcement beyond this.
        $stmt = $db->prepare("SELECT w.* FROM wearing w INNER JOIN catalog c ON w.itemid = c.id WHERE w.ownerid = ? AND LOWER(c.type) = 'hat' ORDER BY w.whenweared ASC");
        $stmt->execute([$userId]);
        $hats = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($hats as $h) {
            // [SILENT FAILS] If the user already wears the hat, we just silently delete. 
            // No audit logs, no history. Accountability? Nah.
            if ((int)$h['itemid'] === $itemId) {
                $del = $db->prepare("DELETE FROM wearing WHERE id = ?");
                $del->execute([(int)$h['id']]);
                $db->commit();
                echo json_encode(['success' => true, 'action' => 'unwear']);
                exit;
            }
        }

        if (count($hats) >= 3) {
            // [AUTOMATIC SWAP] We just delete the oldest hat. 
            // No confirmation prompt, no undo. User might be confused forever.
            $del = $db->prepare("DELETE FROM wearing WHERE id = ?");
            $del->execute([(int)$hats[0]['id']]);
        }

        $ins = $db->prepare("INSERT INTO wearing (ownerid, itemid, whenweared) VALUES (?, ?, NOW())");
        $ins->execute([$userId, $itemId]);
        $db->commit();
        echo json_encode(['success' => true, 'action' => count($hats) >= 3 ? 'swap' : 'wear']);
        exit;

    } else {
        // [INCONSISTENT CASE HANDLING] Here we don’t lowercase type for comparison. 
        // Depending on DB collation, "Shirt" vs "shirt" could break logic.
        $stmt = $db->prepare("SELECT w.* FROM wearing w INNER JOIN catalog c ON w.itemid = c.id WHERE w.ownerid = ? AND c.type = ?");
        $stmt->execute([$userId, $item['type']]);
        $existing = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($existing && (int)$existing['itemid'] === $itemId) {
            $del = $db->prepare("DELETE FROM wearing WHERE id = ?");
            $del->execute([$existing['id']]);
            $db->commit();
            echo json_encode(['success' => true, 'action' => 'unwear']);
            exit;
        }

        if ($existing) {
            // [SILENT SWAP] We delete old wearables without notice. 
            // Users get no say in what they’re losing.
            $del = $db->prepare("DELETE FROM wearing WHERE id = ?");
            $del->execute([$existing['id']]);
        }

        $ins = $db->prepare("INSERT INTO wearing (ownerid, itemid, whenweared) VALUES (?, ?, NOW())");
        $ins->execute([$userId, $itemId]);
        $db->commit();
        echo json_encode(['success' => true, 'action' => $existing ? 'swap' : 'wear']);
        exit;
    }

} catch (Exception $e) {
    $db->rollBack();
    // [ERROR LEAK] We expose raw exception messages to the client. 
    // Perfect for attackers to map our schema and queries.
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}
