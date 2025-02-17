<?php
session_start();

// Konfiguration
require_once 'keyauth.php';
require_once 'credentials.php';

// HTTPS erzwingen (in Produktion)
if ($_SERVER['HTTPS'] !== 'on' && $_SERVER['HTTP_HOST'] !== 'localhost') {
    header("Location: https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
    exit();
}

// Initialisiere KeyAuth
try {
    $KeyAuthApp = new KeyAuth\api($name, $ownerid);
    
    if (!isset($_SESSION['sessionid'])) {
        $KeyAuthApp->init();
    }
} catch (Exception $e) {
    die("KeyAuth Initialisierungsfehler: " . $e->getMessage());
}

// Bereits eingeloggt?
if (isset($_SESSION['user_data'])) {
    header("Location: dashboard/");
    exit();
}

// Verarbeite Formulardaten
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF-Schutz
    if (!isset($_SERVER['HTTP_REFERER']) || parse_url($_SERVER['HTTP_REFERER'], PHP_URL_HOST) !== $_SERVER['HTTP_HOST']) {
        die("Ungültige Anfrage!");
    }

    // Rate Limiting
    $_SESSION['request_count'] = ($_SESSION['request_count'] ?? 0) + 1;
    if ($_SESSION['request_count'] > 5) {
        die("Zu viele Anfragen - bitte warten Sie 10 Minuten");
    }

    // Gemeinsame Verarbeitung
    $action = array_keys($_POST)[0];
    $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
    $password = filter_input(INPUT_POST, 'password', FILTER_SANITIZE_STRING);
    $key = filter_input(INPUT_POST, 'key', FILTER_SANITIZE_STRING);

    try {
        switch ($action) {
            case 'login':
                if (empty($username) || empty($password)) {
                    throw new Exception("Bitte alle Felder ausfüllen!");
                }

                if ($KeyAuthApp->login($username, $password)) {
                    $_SESSION['user_data'] = [
                        'username' => $username,
                        'ip' => $_SERVER['REMOTE_ADDR'],
                        'expiry' => $KeyAuthApp->expiry
                    ];
                    $KeyAuthApp->success("Login erfolgreich!");
                    header("Refresh:2; url=dashboard/");
                }
                break;

            case 'register':
                if (empty($username) || empty($password) || empty($key)) {
                    throw new Exception("Bitte alle Felder ausfüllen!");
                }

                if ($KeyAuthApp->register($username, $password, $key)) {
                    $KeyAuthApp->success("Registrierung erfolgreich!");
                    header("Refresh:2; url=dashboard/");
                }
                break;

            case 'upgrade':
                if (empty($username) || empty($key)) {
                    throw new Exception("Bitte alle Felder ausfüllen!");
                }

                if ($KeyAuthApp->upgrade($username, $key)) {
                    $KeyAuthApp->success("Upgrade erfolgreich!");
                }
                break;

            case 'license':
                if (empty($key)) {
                    throw new Exception("Bitte Lizenzschlüssel eingeben!");
                }

                if ($KeyAuthApp->license($key)) {
                    $_SESSION['user_data'] = [
                        'license' => $key,
                        'ip' => $_SERVER['REMOTE_ADDR'],
                        'expiry' => $KeyAuthApp->expiry
                    ];
                    $KeyAuthApp->success("Lizenz aktiviert!");
                    header("Refresh:2; url=dashboard/");
                }
                break;

            default:
                throw new Exception("Ungültige Aktion");
        }
    } catch (Exception $e) {
        $KeyAuthApp->error($e->getMessage());
    }
}
?>

<!DOCTYPE html>
<html lang="de" class="bg-[#09090d] text-white overflow-x-hidden">
<head>
    <meta charset="UTF-8">
    <title>KeyAuth Login</title>
    <!-- Stile und Skripte wie zuvor -->
</head>
<body>
    <!-- Header-Bereich unverändert -->

    <main class="container mx-auto px-4 py-8">
        <?php if (isset($KeyAuthApp->error)): ?>
            <div class="bg-red-500 text-white p-4 mb-4 rounded">
                <?= htmlspecialchars($KeyAuthApp->error) ?>
            </div>
        <?php endif; ?>

        <?php if (isset($KeyAuthApp->success)): ?>
            <div class="bg-green-500 text-white p-4 mb-4 rounded">
                <?= htmlspecialchars($KeyAuthApp->success) ?>
            </div>
        <?php endif; ?>

        <form method="post" class="max-w-md mx-auto bg-gray-800 p-6 rounded-lg">
            <!-- Formularfelder wie zuvor -->
        </form>
    </main>

    <script>
        // Session-Timeout
        let idleTimeout = 15 * 60 * 1000; // 15 Minuten
        let idleTimer;

        function resetTimer() {
            clearTimeout(idleTimer);
            idleTimer = setTimeout(logoutUser, idleTimeout);
        }

        function logoutUser() {
            window.location.href = 'logout.php';
        }

        document.addEventListener('mousemove', resetTimer);
        document.addEventListener('keypress', resetTimer);
        resetTimer();
    </script>
</body>
</html>