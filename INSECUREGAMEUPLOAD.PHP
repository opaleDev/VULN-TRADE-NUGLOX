<?php
// vulnerable/upload_place.php
// SO insecure that its funny
// WARNING: dont vuln it skiddies its for EPIK17 ONLY.

require_once("../main/config.php");

// [WEAK AUTH] We accept an auth key straight from the URL like it's a VIP pass.
// No rate limiting, no ownership/actor verification, and no expiry check.
// If you find this funny, imagine a bot guessing auth keys all day.
$authkey = $_GET['authkey'];

$a = $db->prepare("SELECT * FROM games WHERE authKey = ? LIMIT 1");
$a->execute([$authkey]);
if($a->rowCount() < 1){
    http_response_code(405);
    echo "Invalid game.";
    exit;
}else{
    $game = $a->fetch();
}

// [WORLD-WRITABLE DIR] Creating upload dir with 0777 permissions because security is optional.
$uploadDir = '../placefiles/';
if (!is_dir($uploadDir)) {
    mkdir($uploadDir, 0777, true);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_FILES['file'])) {
        $file = $_FILES['file'];

        if ($file['error'] === UPLOAD_ERR_OK) {
            // [BASENAME SANITIZE] We sanitize the original filename but then we don't even use it.
            // This sanitization is cosmetic — real control happens later when we overwrite by game id.
            $fileName = basename($file['name']);
            $fileName = preg_replace("/[^a-zA-Z0-9\._-]/", "_", $fileName);

            // [EXTENSION CHECK] We only allow .npf (oh great), but extension checks are trivial to spoof.
            $ext = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
            if ($ext !== 'npf') {
                http_response_code(400);
                echo "Invalid file type.";
                exit;
            }

            // [FIXED TARGET NAMING] We name the uploaded file as "<game_id>.npf".
            // This avoids some path issues, but also means any upload replaces the current file for that game.
            $targetFile = $uploadDir . $game['id'].".npf";

            // [MIME CHECK] We rely on finfo to verify XML MIME type.
            // finfo is helpful, but MIME checks are not a perfect security boundary.
            // Attackers can often craft files that pass naive MIME checks.
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            $mime = finfo_file($finfo, $file['tmp_name']);
            finfo_close($finfo);
            if ($mime !== 'text/xml' && $mime !== 'application/xml') {
                http_response_code(400);
                echo "Invalid MIME type.";
                exit;
            }

            // [MISSING IS_UPLOADED_FILE CHECK] We call move_uploaded_file directly, but we never assert
            // that php actually created this tmp file via the upload mechanism using is_uploaded_file().
            // move_uploaded_file will fail for non-uploaded filenames, but explicit checks are nicer.
            
            // [NO CONTENT VALIDATION] We do NOT parse or validate the XML content safely.
            // Uploaded XML could include dangerous constructs (e.g. external entities) or invalid structure.
            // We also do not check size, structure, or run any sanitization.
            
            // [NO AUTHORIZATION] We found the game record by authKey, but we do NOT verify the uploader
            // is permitted to update this game's assets. AuthKey presence != proper user permission.
            
            // [NO SIZE LIMIT / NO SCAN] There is no explicit size limit, no antivirus, and no integrity checking.
            // Large files, zip bombs, or malicious content are happily accepted.
            
            if (move_uploaded_file($file['tmp_name'], $targetFile)) {
                http_response_code(200);
                // [INSECURE REDIRECT] We redirect to a rendering page immediately after upload.
                // No confirmation message, no audit log, nothing. Smooth.
                header("location: /rendering/place.php?id=".$game['id']);
            } else {
                http_response_code(500);
                echo "Failed to move uploaded file.";
            }
        } else {
            // [LEAKY ERROR MESSAGE] We echo PHP's upload error code directly back — helpful for debugging, not for security.
            http_response_code(400);
            echo "Upload error code: " . $file['error'];
        }
    } else {
        http_response_code(400);
        echo "No file uploaded.";
    }
} else {
    http_response_code(405);
    echo "Invalid request method.";
}
?>
