<?php

/**
 * UHST (User Hosted Session Traversal) Relay Server - PHP Implementation (MySQL)
 *
 * This version uses a MySQL database for state management and message queuing,
 * following the architecture of the NodeJS implementation.
 */

set_time_limit(0);
ignore_user_abort(true);

// --- Configuration ---
$dbHost = getenv('DB_HOST') ?: 'localhost';
$dbName = getenv('DB_NAME') ?: 'uhst';
$dbUser = getenv('DB_USER') ?: 'root';
$dbPass = getenv('DB_PASS') ?: '';
$jwtSecret = getenv('JWT_SECRET') ?: 'default_secret';

// For sandbox testing, we'll use SQLite if MySQL is not available
$dsn = "mysql:host=$dbHost;dbname=$dbName;charset=utf8mb4";
if (getenv('ENVIRONMENT') === 'SANDBOX') {
    $dsn = "sqlite:uhst.db";
}

try {
    $pdo = new PDO($dsn, $dbUser, $dbPass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
} catch (PDOException $e) {
    http_response_code(500);
    exit("Database connection failed: " . $e->getMessage());
}

// --- Database Initialization ---
if ($pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite') {
    $pdo->exec("CREATE TABLE IF NOT EXISTS uhst_hosts (
        host_id VARCHAR(255) PRIMARY KEY,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

    $pdo->exec("CREATE TABLE IF NOT EXISTS uhst_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        recipient_token_hash VARCHAR(64),
        body TEXT,
        response_token TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_recipient ON uhst_messages (recipient_token_hash)");
} else {
    // MySQL
    $pdo->exec("CREATE TABLE IF NOT EXISTS uhst_hosts (
        host_id VARCHAR(255) PRIMARY KEY,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )");

    $pdo->exec("CREATE TABLE IF NOT EXISTS uhst_messages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        recipient_token_hash VARCHAR(64) NOT NULL,
        body TEXT NOT NULL,
        response_token TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_recipient (recipient_token_hash)
    )");
}

// --- JWT Utilities ---
function base64UrlEncode($data) {
    return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($data));
}

function base64UrlDecode($data) {
    $remainder = strlen($data) % 4;
    if ($remainder) {
        $data .= str_repeat('=', 4 - $remainder);
    }
    return base64_decode(str_replace(['-', '_'], ['+', '/'], $data));
}

function signToken($payload) {
    global $jwtSecret;
    $header = base64UrlEncode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
    $payload = base64UrlEncode(json_encode($payload));
    $signature = base64UrlEncode(hash_hmac('sha256', "$header.$payload", $jwtSecret, true));
    return "$header.$payload.$signature";
}

function verifyToken($token) {
    global $jwtSecret;
    $parts = explode('.', $token);
    if (count($parts) !== 3) return null;
    list($header, $payload, $signature) = $parts;
    $expectedSignature = base64UrlEncode(hash_hmac('sha256', "$header.$payload", $jwtSecret, true));
    if ($signature !== $expectedSignature) return null;
    return json_decode(base64UrlDecode($payload), true);
}

function getTokenHash($token) {
    return hash('sha256', $token);
}

// --- Helper Functions ---
function getDbTimestamp($pdo) {
    if ($pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'mysql') {
        return $pdo->query("SELECT UNIX_TIMESTAMP()")->fetchColumn();
    } else {
        return $pdo->query("SELECT strftime('%s', 'now')")->fetchColumn();
    }
}

function isHostConnected($hostId) {
    global $pdo;
    $stmt = $pdo->prepare("SELECT last_seen FROM uhst_hosts WHERE host_id = ?");
    $stmt->execute([$hostId]);
    $lastSeen = $stmt->fetchColumn();
    if (!$lastSeen) return false;

    $now = getDbTimestamp($pdo);
    $lastSeenTs = strtotime($lastSeen . ' UTC');
    return ($now - $lastSeenTs) < 15;
}

function updateHostHeartbeat($hostId) {
    global $pdo;
    if ($pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'mysql') {
        $stmt = $pdo->prepare("INSERT INTO uhst_hosts (host_id, last_seen) VALUES (?, NOW())
                               ON DUPLICATE KEY UPDATE last_seen = NOW()");
    } else {
        $stmt = $pdo->prepare("INSERT INTO uhst_hosts (host_id, last_seen) VALUES (?, datetime('now'))
                               ON CONFLICT(host_id) DO UPDATE SET last_seen = datetime('now')");
    }
    $stmt->execute([$hostId]);
}

// --- Request Handling ---
$action = $_GET['action'] ?? null;
$token = $_GET['token'] ?? null;

// Periodically clean up old data
if (rand(1, 100) === 1) {
    if ($pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'mysql') {
        $pdo->exec("DELETE FROM uhst_messages WHERE created_at < DATE_SUB(NOW(), INTERVAL 1 MINUTE)");
        $pdo->exec("DELETE FROM uhst_hosts WHERE last_seen < DATE_SUB(NOW(), INTERVAL 1 MINUTE)");
    } else {
        $pdo->exec("DELETE FROM uhst_messages WHERE created_at < datetime('now', '-1 minute')");
        $pdo->exec("DELETE FROM uhst_hosts WHERE last_seen < datetime('now', '-1 minute')");
    }
}

// Action: host
if ($action === 'host' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    $hostId = $_GET['hostId'] ?? bin2hex(random_bytes(8));
    if (isHostConnected($hostId)) {
        http_response_code(400);
        exit;
    }
    // We must register the host so it can be 'joined'
    updateHostHeartbeat($hostId);

    $hostToken = signToken(['type' => 'HOST', 'hostId' => $hostId]);
    echo json_encode(['hostId' => $hostId, 'hostToken' => $hostToken]);
    exit;
}

// Action: join
if ($action === 'join' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    $hostId = $_GET['hostId'] ?? '';
    if (!isHostConnected($hostId)) {
        http_response_code(400);
        echo json_encode(['error' => 'Host not found or not connected']);
        exit;
    }
    $clientId = bin2hex(random_bytes(16));
    $clientToken = signToken(['type' => 'CLIENT', 'hostId' => $hostId, 'clientId' => $clientId]);
    echo json_encode(['clientToken' => $clientToken]);
    exit;
}

// Action: ping
if ($action === 'ping') {
    header('Content-Type: application/json');
    $timestamp = $_GET['timestamp'] ?? null;
    echo json_encode(['pong' => $timestamp ? (int)$timestamp : null]);
    exit;
}

// Token-based requests
if ($token) {
    $decoded = verifyToken($token);
    if (!$decoded) {
        http_response_code(401);
        exit;
    }

    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        // SSE Listen
        header('Content-Type: text/event-stream');
        header('Cache-Control: no-cache');
        header('Connection: keep-alive');
        header('X-Accel-Buffering: no');

        echo ": Connected.\n\n";
        if (ob_get_level() > 0) ob_flush();
        flush();

        $tokenHash = getTokenHash($token);
        $lastHeartbeat = 0;

        while (true) {
            if (connection_aborted()) break;

            // Heartbeat
            if (time() - $lastHeartbeat >= 5) {
                echo ": sse-keep-alive\n\n";
                if (ob_get_level() > 0) ob_flush();
                flush();
                $lastHeartbeat = time();

                if ($decoded['type'] === 'HOST') {
                    updateHostHeartbeat($decoded['hostId']);
                }
            }

            // Fetch messages
            $stmt = $pdo->prepare("SELECT id, body, response_token FROM uhst_messages WHERE recipient_token_hash = ? ORDER BY id ASC");
            $stmt->execute([$tokenHash]);
            $messages = $stmt->fetchAll();

            if ($messages) {
                $ids = [];
                foreach ($messages as $msg) {
                    $payload = ['body' => json_decode($msg['body'])];
                    if ($msg['response_token']) {
                        $payload['responseToken'] = $msg['response_token'];
                    }
                    echo "data: " . json_encode($payload) . "\n\n";
                    $ids[] = $msg['id'];
                }
                if (ob_get_level() > 0) ob_flush();
                flush();

                // Delete delivered messages
                $placeholders = implode(',', array_fill(0, count($ids), '?'));
                $pdo->prepare("DELETE FROM uhst_messages WHERE id IN ($placeholders)")->execute($ids);
            }

            usleep(20000); // 20ms for low latency
        }
        exit;
    } elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // Send Message
        header('Content-Type: application/json');
        $body = file_get_contents('php://input');

        if ($decoded['type'] === 'CLIENT') {
            // Client to Host
            $hostId = $decoded['hostId'];
            $clientId = $decoded['clientId'];
            $hostToken = signToken(['type' => 'HOST', 'hostId' => $hostId]);
            $hostTokenHash = getTokenHash($hostToken);

            $responseToken = signToken(['type' => 'RESPONSE', 'hostId' => $hostId, 'clientId' => $clientId]);

            $stmt = $pdo->prepare("INSERT INTO uhst_messages (recipient_token_hash, body, response_token) VALUES (?, ?, ?)");
            $stmt->execute([$hostTokenHash, $body, $responseToken]);
        } elseif ($decoded['type'] === 'RESPONSE') {
            // Host to Client (targeted)
            $hostId = $decoded['hostId'];
            $clientId = $decoded['clientId'];
            $clientToken = signToken(['type' => 'CLIENT', 'hostId' => $hostId, 'clientId' => $clientId]);
            $clientTokenHash = getTokenHash($clientToken);

            $stmt = $pdo->prepare("INSERT INTO uhst_messages (recipient_token_hash, body) VALUES (?, ?)");
            $stmt->execute([$clientTokenHash, $body]);
        }

        echo json_encode((object)[]);
        exit;
    }
}

http_response_code(400);
echo "Invalid request";
