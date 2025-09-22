<?php
// vulnerable/change_character.php
// "caca"
// WARNING: THIS CODE BELONGS TO EPIK

include 'main/nav.php';

// [LOGIN CHECK] Only checks $isloggedin, no CSRF protection for POST forms.
// Anyone can trick a logged-in user into submitting changes.
if (!$isloggedin) {
    header("location: /");
    exit;
}

// [ENUM PARSING] We pull enum values from DB dynamically. Cute, but could break if DB changes.
$bodyTypeEnum = [];
$enumQuery = $db->query("SHOW COLUMNS FROM users LIKE 'bodytype'");
$enumRow = $enumQuery->fetch(PDO::FETCH_ASSOC);
if ($enumRow && preg_match("/^enum\((.*)\)$/", $enumRow['Type'], $matches)) {
    $values = explode(",", $matches[1]);
    foreach ($values as $value) {
        $bodyTypeEnum[] = trim($value, " '");
    }
}

// [TRUSTING CLIENT DATA] All colors and bodyType come straight from POST. No validation besides enum check for bodyType.
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $colors = [
        'head' => $_POST['headColor'] ?? '#d2a679',
        'torso' => $_POST['torsoColor'] ?? '#0066cc',
        'leftArm' => $_POST['leftArmColor'] ?? '#d2a679',
        'rightArm' => $_POST['rightArmColor'] ?? '#d2a679',
        'leftLeg' => $_POST['leftLegColor'] ?? '#cc0000',
        'rightLeg' => $_POST['rightLegColor'] ?? '#cc0000',
    ];

    $selectedBodyType = $_POST['bodyType'] ?? ($bodyTypeEnum[0] ?? 'blocky');
    if (!in_array($selectedBodyType, $bodyTypeEnum, true)) {
        $selectedBodyType = $bodyTypeEnum[0] ?? 'blocky';
    }

    // [BLIND UPDATE] Directly updates DB with all user-supplied colors. No rate-limit, no validation on hex codes.
    $stmt = $db->prepare("UPDATE users SET headc = ?, torsoc = ?, leftarmc = ?, rightarmc = ?, leftlegc = ?, rightlegc = ?, bodytype = ? WHERE id = ?");
    $stmt->execute([
        $colors['head'], $colors['torso'], $colors['leftArm'], $colors['rightArm'],
        $colors['leftLeg'], $colors['rightLeg'], $selectedBodyType, $user->id
    ]);

    header('Content-Type: application/json');
    echo json_encode(['success' => true]);
    exit;
}

// [HELPER FUNCTIONS] For fetching current colors and items. No caching, multiple queries for same data (performance meh).
function getUserColorsAndBodyType($user) { //blublublublbulbu lazypreview
    return [
        'colors' => [
            'head' => $user->headc ?: '#d2a679',
            'torso' => $user->torsoc ?: '#0066cc',
            'leftArm' => $user->leftarmc ?: '#d2a679',
            'rightArm' => $user->rightarmc ?: '#d2a679',
            'leftLeg' => $user->leftlegc ?: '#cc0000',
            'rightLeg' => $user->rightlegc ?: '#cc0000',
        ],
        'bodyType' => $user->bodytype ?: ($GLOBALS['bodyTypeEnum'][0] ?? 'blocky')
    ];
}

function getWearingAndInventory($db, $userId) {
    $wearing = $db->prepare("SELECT c.id, c.name FROM catalog c INNER JOIN wearing w ON w.itemid = c.id WHERE w.ownerid = ? ORDER BY w.whenweared DESC");
    $wearing->execute([$userId]);
    $wearingItems = $wearing->fetchAll(PDO::FETCH_ASSOC);

    $inventory = $db->prepare("SELECT c.id, c.name FROM catalog c INNER JOIN inventory i ON i.itemid = c.id WHERE i.ownerid = ? ORDER BY i.whenbought DESC");
    $inventory->execute([$userId]);
    $inventoryItems = $inventory->fetchAll(PDO::FETCH_ASSOC);

    return ['wearing' => $wearingItems, 'inventory' => $inventoryItems];
}

// Fetch initial data for rendering page
$colorsAndBodyType = getUserColorsAndBodyType($user);
$colors = $colorsAndBodyType['colors'];
$selectedBodyType = $colorsAndBodyType['bodyType'];

$wearingAndInventory = getWearingAndInventory($db, $user->id);
$wearingItems = $wearingAndInventory['wearing'];
$inventoryItems = $wearingAndInventory['inventory'];

// [AJAX ENDPOINT] Returns wearing/inventory JSON. No authentication beyond login check.
if (isset($_GET['ajax']) && $_GET['ajax'] == '1') {
    header('Content-Type: application/json');
    echo json_encode([
        'success' => true,
        'wearing' => $wearingItems,
        'inventory' => $inventoryItems
    ]);
    exit;
}
?>
