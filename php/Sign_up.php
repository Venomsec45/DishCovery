<?php
  include("database.php");
  session_start();
  $signup_error = '';

  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $first = trim($_POST['first_name'] ?? '');
    $last = trim($_POST['last_name'] ?? '');
    $email = trim($_POST['email_address'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm = $_POST['confirm_password'] ?? '';

    if (!$first || !$last || !$email || !$password || !$confirm) {
      $signup_error = 'All fields are required.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
      $signup_error = 'Please enter a valid email address.';
    } elseif ($password !== $confirm) {
      $signup_error = 'Passwords do not match.';
    } elseif (strlen($password) < 10) {
      $signup_error = 'Password must be at least 10 characters.';
    } else {
      // Check if email already exists
      $stmt = mysqli_prepare($conn, "SELECT id FROM users WHERE email = ?");
      if ($stmt) {
        mysqli_stmt_bind_param($stmt, "s", $email);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_store_result($stmt);
        if (mysqli_stmt_num_rows($stmt) > 0) {
          $signup_error = 'Email is already registered.';
          mysqli_stmt_close($stmt);
        } else {
          mysqli_stmt_close($stmt);
          $hash = password_hash($password, PASSWORD_DEFAULT);
          $ins = mysqli_prepare($conn, "INSERT INTO users (first_name, last_name, email, password) VALUES (?, ?, ?, ?)");
          if ($ins) {
            mysqli_stmt_bind_param($ins, "ssss", $first, $last, $email, $hash);
            if (mysqli_stmt_execute($ins)) {
              mysqli_stmt_close($ins);
              $_SESSION['user_email'] = $email;
              header("Location: account/account_dashboard.html");
              exit;
            } else {
              $signup_error = 'Unable to create account. Please try again later.';
            }
          } else {
            $signup_error = 'Database error. Please try again later.';
          }
        }
      } else {
        $signup_error = 'Database error. Please try again later.';
      }
    }
  }
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DishCovery Website</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="design/sign_up.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@100..900&family=Lexend:wght@100..900&family=Outfit:wght@100..900&display=swap" rel="stylesheet">
</head>

<body class="flex flex-col min-h-screen font-['Outfit'] bg-gray-50 text-gray-800">
  <header class="flex items-center justify-between px-[6vw] py-10 bg-white border-b border-gray-200 sticky top-0 z-50">
    <h1 class="text-2xl font-bold text-[#333] tracking-tight text-[35px]">DishCovery</h1>
  </header>

  <main class="flex-grow flex items-center justify-center px-6 py-12">
    <form
      action="Sign_Up.php"
      method="post"
      class="bg-white shadow-xl rounded-2xl p-8 w-full max-w-md space-y-5 transform transition duration-500 hover:scale-[1.02]"
    >
      <h2 class="text-2xl font-semibold text-center">One account, many dishes</h2>
      <p class="text-gray-500 text-center">Create an account to start your culinary journey</p>
      <?php if (!empty($signup_error)): ?>
        <div class="text-red-600 text-sm text-center"><?php echo htmlspecialchars($signup_error); ?></div>
      <?php endif; ?>

      <div class="flex flex-col space-y-3">
        <button
          type="button"
          class="flex items-center justify-center border border-gray-300 rounded-lg py-2 hover:bg-gray-100 transition"
        >
          <svg class="w-5 h-5 mr-2 text-gray-700" viewBox="0 0 24 24" fill="currentColor">
            <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
            <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
            <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
            <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
          </svg>
          Sign up with Google
        </button>
        <button
          type="button"
          class="flex items-center justify-center border border-gray-300 rounded-lg py-2 hover:bg-gray-100 transition"
        >
          <svg class="w-5 h-5 mr-2 text-gray-700" fill="currentColor" viewBox="0 0 24 24">
            <path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z"/>
          </svg>
          Sign up with Facebook
        </button>
      </div>

      <div class="flex items-center my-3">
        <hr class="flex-grow border-gray-300" />
        <span class="mx-3 text-gray-500 text-sm">or continue with email</span>
        <hr class="flex-grow border-gray-300" />
      </div>

      <div class="grid grid-cols-2 gap-3">
        <div>
          <label for="first_name" class="block text-sm font-medium">First name</label>
          <input
            type="text"
            id="first_name"
            name="first_name"
            required
            class="w-full border border-gray-300 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-orange-400"
          />
        </div>

        <div>
          <label for="last_name" class="block text-sm font-medium">Last name</label>
          <input
            type="text"
            id="last_name"
            name="last_name"
            required
            class="w-full border border-gray-300 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-orange-400"
          />
        </div>
      </div>

      <div>
        <label for="email_address" class="block text-sm font-medium">Email address</label>
        <input
          type="email"
          id="email_address"
          name="email_address"
          required
          class="w-full border border-gray-300 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-orange-400"
        />
      </div>

      <div>
        <label for="password" class="block text-sm font-medium">Password</label>
        <input
          type="password"
          id="password"
          name="password"
          minlength="10"
          required
          class="w-full border border-gray-300 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-orange-400"
        />
      </div>

      <div>
        <label for="confirm_password" class="block text-sm font-medium">Confirm password</label>
        <input
          type="password"
          id="confirm_password"
          name="confirm_password"
          required
          class="w-full border border-gray-300 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-orange-400"
        />
      </div>

      <label class="flex items-center text-sm">
        <input type="checkbox" id="agreement" name="agreement" required class="mr-2 text-orange-500 focus:ring-orange-400" />
        I agree to the
        <a href="#" class="text-orange-500 hover:underline mx-1">Terms of Service</a>
        and the 
        <a href="#" class="text-orange-500 hover:underline mx-1">Privacy Policy</a>
      </label>

      <button
        type="submit"
        class="w-full bg-gradient-to-r from-orange-500 to-orange-600 text-white py-2 rounded-lg font-medium hover:opacity-90 transition"
      >
        Create Account
      </button>

      <div class="text-center">
        <a href="Log_In.php" class="text-sm text-gray-500 hover:underline">Back</a>
      </div>
    </form>
  </main>

  <footer class="bg-gray-800 text-white py-12 mt-auto">
  <div class="max-w-6xl mx-auto px-6 flex flex-col md:flex-row justify-between items-start gap-8 text-sm">
    
    <!-- Left column -->
    <div class="md:w-1/2">
      <p>
        Discover amazing recipes, explore culinary adventures, and find your next favorite dish with our comprehensive recipe platform that reduces food waste and enhances cooking creativity.
      </p>
    </div>

    <!-- Right column -->
    <div class="md:w-1/2 flex flex-col md:flex-row justify-between">
      <div>
        <h3 class="font-semibold mb-2 text-orange-400">Contact Info</h3>
        <p>hello@dishcovery.com</p>
        <p>+1 (555) 123-4567</p>
        <p>123 Culinary Street, Food City</p>
      </div>

      <div class="text-left">
        <h3 class="font-semibold mb-2 text-orange-400">Follow Us</h3>
        <div class="space-x-3">
          <a href="#" class="hover:underline">Facebook</a>
          <a href="#" class="hover:underline">Twitter</a>
          <a href="#" class="hover:underline">Instagram</a>
        </div>
      </div>
    </div>
  </div>

  <div class="border-t border-gray-700 mt-8 pt-4 text-sm flex flex-col md:flex-row justify-between items-center max-w-6xl mx-auto px-6">
    <p class="mb-2 md:mb-0">© 2025 DishCovery. All rights reserved.</p>
    <div class="space-x-4">
      <a href="#" class="hover:underline">Privacy Policy</a>
      <a href="#" class="hover:underline">Terms of Service</a>
    </div>
  </div>
</footer>

</body>
</html>