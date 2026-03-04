<?php

/**
 * UHST (User Hosted Session Traversal) Relay Server - PHP Implementation
 *
 * This is a lightweight, dependency-free signaling server that uses local files
 * for coordination. It supports SSE for message delivery and is suitable for
 * shared hosting environments.
 */

set_time_limit(0);

$dataDir = __DIR__ . '/data';
if (!is_dir($dataDir)) {
    mkdir($dataDir, 0777, true);
}

$action = $_GET['action'] ?? null;
$token = $_GET['token'] ?? null;
$hostId = $_GET['hostId'] ?? null;

// Sanitize inputs to prevent path traversal
if ($token && !preg_match('/^[a-zA-Z0-9_\-]+$/', $token)) {
    http_response_code(400);
    exit("Invalid token format");
}
if ($hostId && !preg_match('/^[a-zA-Z0-9_\-]+$/', $hostId)) {
    http_response_code(400);
    exit("Invalid hostId format");
}

// Cleanup old files periodically (1% chance per request)
if (rand(1, 100) === 1) {
    $now = time();
    $files = glob("$dataDir/*");
    if ($files) {
        foreach ($files as $file) {
            if (filemtime($file) < $now - 60) {
                @unlink($file);
            }
        }
    }
}

/**
 * Reads a JSON file with a shared lock.
 */
function getSafe($path) {
    if (!file_exists($path)) return null;
    @touch($path);
    $fp = fopen($path, 'rb');
    if (!$fp) return null;
    flock($fp, LOCK_SH);
    $content = stream_get_contents($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    return json_decode($content, true);
}

/**
 * Writes data to a JSON file with an exclusive lock.
 */
function saveSafe($path, $data) {
    $fp = fopen($path, 'cb');
    if (!$fp) return false;
    flock($fp, LOCK_EX);
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($data));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    return true;
}

/**
 * Appends a message to a token's queue.
 */
function appendMessage($token, $message) {
    global $dataDir;
    $path = "$dataDir/queue_$token.json";
    $fp = fopen($path, 'cb+');
    if (!$fp) return false;
    flock($fp, LOCK_EX);
    $content = stream_get_contents($fp);
    $queue = json_decode($content, true) ?: [];
    $queue[] = $message;
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($queue));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    return true;
}

/**
 * Pops all messages from a token's queue.
 */
function popMessages($token) {
    global $dataDir;
    $path = "$dataDir/queue_$token.json";
    if (!file_exists($path)) return [];
    $fp = fopen($path, 'cb+');
    if (!$fp) return [];
    flock($fp, LOCK_EX);
    $content = stream_get_contents($fp);
    $queue = json_decode($content, true) ?: [];
    if (!empty($queue)) {
        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, json_encode([]));
        fflush($fp);
    }
    flock($fp, LOCK_UN);
    fclose($fp);
    return $queue;
}

// Handle Action: host
if ($action === 'host' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    $hId = bin2hex(random_bytes(8));
    $hToken = bin2hex(random_bytes(16));
    saveSafe("$dataDir/host_$hId.json", ['hostToken' => $hToken]);
    saveSafe("$dataDir/token_$hToken.json", ['type' => 'host', 'hostId' => $hId]);
    echo json_encode(['hostId' => $hId, 'hostToken' => $hToken]);
    exit;
}

// Handle Action: join
if ($action === 'join' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    if (!$hostId) {
        http_response_code(400);
        echo json_encode(['error' => 'hostId is required']);
        exit;
    }
    $hostData = getSafe("$dataDir/host_$hostId.json");
    if (!$hostData) {
        http_response_code(404);
        echo json_encode(['error' => 'Host not found']);
        exit;
    }
    $clientToken = bin2hex(random_bytes(16));
    saveSafe("$dataDir/token_$clientToken.json", [
        'type' => 'client',
        'hostToken' => $hostData['hostToken'],
        'hostId' => $hostId
    ]);
    echo json_encode(['clientToken' => $clientToken]);
    exit;
}

// Handle Action: ping
if ($action === 'ping') {
    echo "OK";
    exit;
}

// Handle Token-based requests (SSE and Send Message)
if ($token) {
    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        // SSE Connection
        header('Content-Type: text/event-stream');
        header('Cache-Control: no-cache');
        header('Connection: keep-alive');
        header('X-Accel-Buffering: no');

        echo ": Connected.\n\n";
        if (ob_get_level() > 0) ob_flush();
        flush();

        $lastKeepAlive = time();
        while (true) {
            if (connection_aborted()) break;

            $messages = popMessages($token);
            if (!empty($messages)) {
                foreach ($messages as $msg) {
                    echo "data: " . json_encode($msg) . "\n\n";
                }
                if (ob_get_level() > 0) ob_flush();
                flush();
            }

            $now = time();
            if ($now - $lastKeepAlive >= 5) {
                echo ": sse-keep-alive\n\n";
                if (ob_get_level() > 0) ob_flush();
                flush();
                $lastKeepAlive = $now;

                // Keep token file alive
                @touch("$dataDir/token_$token.json");

                // Also keep related host file alive if applicable
                $tokenData = getSafe("$dataDir/token_$token.json");
                if ($tokenData && $tokenData['type'] === 'host') {
                    @touch("$dataDir/host_" . $tokenData['hostId'] . ".json");
                }
            }

            usleep(20000); // 20ms for low latency
        }
        exit;
    } elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // Send Message
        header('Content-Type: application/json');
        $input = json_decode(file_get_contents('php://input'), true);
        $tokenData = getSafe("$dataDir/token_$token.json");

        if ($tokenData) {
            if ($tokenData['type'] === 'client') {
                // From Client to Host
                $hostToken = $tokenData['hostToken'];
                // Use a stable response token for this client
                $responseToken = 'res_' . $token;
                if (!file_exists("$dataDir/token_$responseToken.json")) {
                    saveSafe("$dataDir/token_$responseToken.json", [
                        'type' => 'response',
                        'clientToken' => $token
                    ]);
                } else {
                    @touch("$dataDir/token_$responseToken.json");
                }

                appendMessage($hostToken, [
                    'body' => $input,
                    'responseToken' => $responseToken
                ]);
            } elseif ($tokenData['type'] === 'response') {
                // From Host to Client
                $clientToken = $tokenData['clientToken'];
                appendMessage($clientToken, [
                    'body' => $input
                ]);
            }
        }
        echo json_encode(['status' => 'sent']);
        exit;
    }
}

http_response_code(400);
echo "Invalid request";
