<?php
error_reporting(0);

echo '<script src="https://cdn.tailwindcss.com"></script>';
/**
 * Class OneFileLoginApplication
 *
 * An entire php application with user registration, login and logout in one file.
 * Uses very modern password hashing via the PHP 5.5 password hashing functions.
 * This project includes a compatibility file to make these functions available in PHP 5.3.7+ and PHP 5.4+.
 *
 * @author Panique
 * @link https://github.com/panique/php-login-one-file/
 * @license http://opensource.org/licenses/MIT MIT License
 */
class OneFileLoginApplication
{
    /**
     * @var string Type of used database (currently only SQLite, but feel free to expand this with mysql etc)
     */
    private $db_type = "sqlite"; //

    /**
     * @var string Path of the database file (create this with _install.php)
     */
    private $db_sqlite_path = "./users.db";

    /**
     * @var object Database connection
     */
    private $db_connection = null;

    /**
     * @var bool Login status of user
     */
    private $user_is_logged_in = false;

    /**
     * @var string System messages, likes errors, notices, etc.
     */
    public $feedback = "";


    /**
     * Does necessary checks for PHP version and PHP password compatibility library and runs the application
     */
    public function __construct()
    {
        if ($this->performMinimumRequirementsCheck()) {
            $this->runApplication();
        }
    }

    /**
     * Performs a check for minimum requirements to run this application.
     * Does not run the further application when PHP version is lower than 5.3.7
     * Does include the PHP password compatibility library when PHP version lower than 5.5.0
     * (this library adds the PHP 5.5 password hashing functions to older versions of PHP)
     * @return bool Success status of minimum requirements check, default is false
     */
    private function performMinimumRequirementsCheck()
    {
        if (version_compare(PHP_VERSION, '5.3.7', '<')) {
            echo "Sorry, Simple PHP Login does not run on a PHP version older than 5.3.7 !";
        } elseif (version_compare(PHP_VERSION, '5.5.0', '<')) {
            require_once("libraries/password_compatibility_library.php");
            return true;
        } elseif (version_compare(PHP_VERSION, '5.5.0', '>=')) {
            return true;
        }
        // default return
        return false;
    }

    /**
     * This is basically the controller that handles the entire flow of the application.
     */
    public function runApplication()
    {
        // check is user wants to see register page (etc.)
        if (isset($_GET["action"]) && $_GET["action"] == "register") {
            $this->doRegistration();
            $this->showPageRegistration();
        } else {
            // start the session, always needed!
            $this->doStartSession();
            // check for possible user interactions (login with session/post data or logout)
            $this->performUserLoginAction();
            // show "page", according to user's login status
            if ($this->getUserLoginStatus()) {
                $this->showPageLoggedIn();
            } else {
                $this->showPageLoginForm();
            }
        }
    }

    /**
     * Creates a PDO database connection (in this case to a SQLite flat-file database)
     * @return bool Database creation success status, false by default
     */
    private function createDatabaseConnection()
    {
        try {
            $this->db_connection = new PDO($this->db_type . ':' . $this->db_sqlite_path);
            return true;
        } catch (PDOException $e) {
            $this->feedback = "PDO database connection problem: " . $e->getMessage();
        } catch (Exception $e) {
            $this->feedback = "General problem: " . $e->getMessage();
        }
        return false;
    }

    /**
     * Handles the flow of the login/logout process. According to the circumstances, a logout, a login with session
     * data or a login with post data will be performed
     */
    private function performUserLoginAction()
    {
        if (isset($_GET["action"]) && $_GET["action"] == "logout") {
            $this->doLogout();
        } elseif (!empty($_SESSION['user_name']) && ($_SESSION['user_is_logged_in'])) {
            $this->doLoginWithSessionData();
        } elseif (isset($_POST["login"])) {
            $this->doLoginWithPostData();
        }
    }

    /**
     * Simply starts the session.
     * It's cleaner to put this into a method than writing it directly into runApplication()
     */
    private function doStartSession()
    {
        if(session_status() == PHP_SESSION_NONE) session_start();
    }

    /**
     * Set a marker (NOTE: is this method necessary ?)
     */
    private function doLoginWithSessionData()
    {
        $this->user_is_logged_in = true; // ?
    }

    /**
     * Process flow of login with POST data
     */
    private function doLoginWithPostData()
    {
        if ($this->checkLoginFormDataNotEmpty()) {
            if ($this->createDatabaseConnection()) {
                $this->checkPasswordCorrectnessAndLogin();
            }
        }
    }

    /**
     * Logs the user out
     */
    private function doLogout()
    {
        $_SESSION = array();
        session_destroy();
        $this->user_is_logged_in = false;
        $this->feedback = "You were just logged out.";
    }

    /**
     * The registration flow
     * @return bool
     */
    private function doRegistration()
    {
        if ($this->checkRegistrationData()) {
            if ($this->createDatabaseConnection()) {
                $this->createNewUser();
            }
        }
        // default return
        return false;
    }

    /**
     * Validates the login form data, checks if username and password are provided
     * @return bool Login form data check success state
     */
    private function checkLoginFormDataNotEmpty()
    {
        if (!empty($_POST['user_name']) && !empty($_POST['user_password'])) {
            return true;
        } elseif (empty($_POST['user_name'])) {
            $this->feedback = "Username field was empty.";
        } elseif (empty($_POST['user_password'])) {
            $this->feedback = "Password field was empty.";
        }
        // default return
        return false;
    }

    /**
     * Checks if user exits, if so: check if provided password matches the one in the database
     * @return bool User login success status
     */
    private function checkPasswordCorrectnessAndLogin()
    {
        // remember: the user can log in with username or email address
        $sql = 'SELECT user_name, user_email, user_password_hash
                FROM users
                WHERE user_name = :user_name OR user_email = :user_name
                LIMIT 1';
        $query = $this->db_connection->prepare($sql);
        $query->bindValue(':user_name', $_POST['user_name']);
        $query->execute();

        // Btw that's the weird way to get num_rows in PDO with SQLite:
        // if (count($query->fetchAll(PDO::FETCH_NUM)) == 1) {
        // Holy! But that's how it is. $result->numRows() works with SQLite pure, but not with SQLite PDO.
        // This is so crappy, but that's how PDO works.
        // As there is no numRows() in SQLite/PDO (!!) we have to do it this way:
        // If you meet the inventor of PDO, punch him. Seriously.
        $result_row = $query->fetchObject();
        if ($result_row) {
            // using PHP 5.5's password_verify() function to check password
            if (password_verify($_POST['user_password'], $result_row->user_password_hash)) {
                // write user data into PHP SESSION [a file on your server]
                $_SESSION['user_name'] = $result_row->user_name;
                $_SESSION['user_email'] = $result_row->user_email;
                $_SESSION['user_is_logged_in'] = true;
                $this->user_is_logged_in = true;
                return true;
            } else {
                $this->feedback = "Wrong password.";
            }
        } else {
            $this->feedback = "This user does not exist.";
        }
        // default return
        return false;
    }

    /**
     * Validates the user's registration input
     * @return bool Success status of user's registration data validation
     */
    private function checkRegistrationData()
    {
        // if no registration form submitted: exit the method
        if (!isset($_POST["register"])) {
            return false;
        }

        // validating the input
        if (!empty($_POST['user_name'])
            && strlen($_POST['user_name']) <= 64
            && strlen($_POST['user_name']) >= 2
            && preg_match('/^[a-z\d]{2,64}$/i', $_POST['user_name'])
            && !empty($_POST['user_email'])
            && strlen($_POST['user_email']) <= 64
            && filter_var($_POST['user_email'], FILTER_VALIDATE_EMAIL)
            && !empty($_POST['user_password_new'])
            && strlen($_POST['user_password_new']) >= 6
            && !empty($_POST['user_password_repeat'])
            && ($_POST['user_password_new'] === $_POST['user_password_repeat'])
        ) {
            // only this case return true, only this case is valid
            return true;
        } elseif (empty($_POST['user_name'])) {
            $this->feedback = "Empty Username";
        } elseif (empty($_POST['user_password_new']) || empty($_POST['user_password_repeat'])) {
            $this->feedback = "Empty Password";
        } elseif ($_POST['user_password_new'] !== $_POST['user_password_repeat']) {
            $this->feedback = "Password and password repeat are not the same";
        } elseif (strlen($_POST['user_password_new']) < 6) {
            $this->feedback = "Password has a minimum length of 6 characters";
        } elseif (strlen($_POST['user_name']) > 64 || strlen($_POST['user_name']) < 2) {
            $this->feedback = "Username cannot be shorter than 2 or longer than 64 characters";
        } elseif (!preg_match('/^[a-z\d]{2,64}$/i', $_POST['user_name'])) {
            $this->feedback = "Username does not fit the name scheme: only a-Z and numbers are allowed, 2 to 64 characters";
        } elseif (empty($_POST['user_email'])) {
            $this->feedback = "Email cannot be empty";
        } elseif (strlen($_POST['user_email']) > 64) {
            $this->feedback = "Email cannot be longer than 64 characters";
        } elseif (!filter_var($_POST['user_email'], FILTER_VALIDATE_EMAIL)) {
            $this->feedback = "Your email address is not in a valid email format";
        } else {
            $this->feedback = "An unknown error occurred.";
        }

        // default return
        return false;
    }

    /**
     * Creates a new user.
     * @return bool Success status of user registration
     */
    private function createNewUser()
    {
        // remove html code etc. from username and email
        $user_name = htmlentities($_POST['user_name'], ENT_QUOTES);
        $user_email = htmlentities($_POST['user_email'], ENT_QUOTES);
        $user_password = $_POST['user_password_new'];
        // crypt the user's password with the PHP 5.5's password_hash() function, results in a 60 char hash string.
        // the constant PASSWORD_DEFAULT comes from PHP 5.5 or the password_compatibility_library
        $user_password_hash = password_hash($user_password, PASSWORD_DEFAULT);

        $sql = 'SELECT * FROM users WHERE user_name = :user_name OR user_email = :user_email';
        $query = $this->db_connection->prepare($sql);
        $query->bindValue(':user_name', $user_name);
        $query->bindValue(':user_email', $user_email);
        $query->execute();

        // As there is no numRows() in SQLite/PDO (!!) we have to do it this way:
        // If you meet the inventor of PDO, punch him. Seriously.
        $result_row = $query->fetchObject();
        if ($result_row) {
            $this->feedback = "Sorry, that username / email is already taken. Please choose another one.";
        } else {
            $sql = 'INSERT INTO users (user_name, user_password_hash, user_email)
                    VALUES(:user_name, :user_password_hash, :user_email)';
            $query = $this->db_connection->prepare($sql);
            $query->bindValue(':user_name', $user_name);
            $query->bindValue(':user_password_hash', $user_password_hash);
            $query->bindValue(':user_email', $user_email);
            // PDO's execute() gives back TRUE when successful, FALSE when not
            // @link http://stackoverflow.com/q/1661863/1114320
            $registration_success_state = $query->execute();

            if ($registration_success_state) {
                $this->feedback = "Your account has been created successfully. You can now log in.";
                return true;
            } else {
                $this->feedback = "Sorry, your registration failed. Please go back and try again.";
            }
        }
        // default return
        return false;
    }

    /**
     * Simply returns the current status of the user's login
     * @return bool User's login status
     */
    public function getUserLoginStatus()
    {
        return $this->user_is_logged_in;
    }

    /**
     * Simple demo-"page" that will be shown when the user is logged in.
     * In a real application you would probably include an html-template here, but for this extremely simple
     * demo the "echo" statements are totally okay.
     */
    private function showPageLoggedIn()
    {
        if ($this->feedback) {
            echo $this->feedback . "<br/><br/>";
        }

echo '<nav class="bg-white fixed w-full border-gray-200 px-2 sm:px-4 py-2.5">';
echo '<div class="lg:max-w-screen-lg md:max-w-screen-md flex flex-wrap justify-between items-center mx-auto">';
echo '<a href="#" class="flex">';
echo '<span class="self-center text-lg font-semibold whitespace-nowrap">Thea</span>';
echo '</a>';
echo '<div class="flex items-center md:order-2">';
echo '<button type="button" class="group relative flex mr-3 text-sm bg-gray-800 rounded-full md:mr-0 focus:ring-4 focus:ring-gray-300" id="user-menu-button" aria-expanded="false" type="button" data-dropdown-toggle="dropdown">';
echo '<span class="sr-only">Open user menu</span>';
echo '<img class="w-8 h-8 rounded-full hover:ring-4 ring-gray-200 object-cover" src="https://images.unsplash.com/photo-1612896488082-7271dc0ed30c?ixlib=rb-1.2.1&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1528&q=80" alt="user photo" />';
echo '<div class="hidden group-hover:block top-6 right-3 border border-gray-50 overflow-hidden shadow-md bg-white ring-0 rounded-xl w-48 absolute">';
echo '<div class="p-3 border-b hover:bg-gray-50">User Details</div>';
echo '<div class="p-3 border-b hover:bg-gray-50 md:hidden">Dashboard</div>';
echo '<div class="p-3 border-b hover:bg-gray-50 md:hidden">To-do</div>';
echo '<div class="p-3 border-b hover:bg-gray-50 md:hidden">Notes</div>';
echo '';
echo '<a href="' . $_SERVER['SCRIPT_NAME'] . '?action=logout" class="p-3 block hover:bg-gray-50">Logout</a>';
echo '</div>';
echo '</button>';
echo '</div>';
echo '<div class="hidden justify-between items-center w-full md:flex md:w-auto md:order-1" id="mobile-menu-2">';
echo '<ul class="flex flex-col mt-4 md:flex-row md:space-x-8 md:mt-0 md:text-sm md:font-medium">';
echo '<li>';
echo '<a href="#" class="block py-2 pr-4 pl-3 rounded text-gray-500 md:p-0" aria-current="page">Dashboard</a>';
echo '</li>';
echo '<li>';
echo '<a href="#" class="block py-2 pr-4 pl-3 rounded text-gray-500 md:p-0" aria-current="page">To-do</a>';
echo '</li>';
echo '<li class="relative">';
echo '<a href="#" class="block py-2 pr-4 pl-3 rounded text-gray-500 md:p-0" aria-current="page">Notes';
echo '</a>';
echo '</a>';
echo '</li>';
echo '<li class="relative group">';
echo '<a href="#" class="block py-2 pr-4 pl-3 rounded text-gray-500 md:p-0" aria-current="page">Calendar</a>';
echo '</li>';
echo '</ul>';
echo '</div>';
echo '</div>';
echo '</nav>';
echo '<div class="px-2 sm:px-4 py-2.5">';
echo '<div class="lg:max-w-screen-lg md:max-w-screen-md mx-auto">';
echo '<h1 class="text-5xl pt-24 pb-12 font-extralight text-gray-700">Welcome to your dashboard <b>@' . $_SESSION['user_name'] . '</b></h1>';
echo '<div>';
echo '<h3 class="text-3xl pb-4 font-semibold tracking-tight">Your timetable:</h3>';
echo '<div class="flex rounded-2xl shadow-md border-gray-100 border divide-x max-w-[1008px] overflow-scroll text-center">';
echo '<div>';
echo '<div class="p-4 font-medium bg-gray-100 w-36">-</div>';
echo '<div class="px-4 py-3 border-t">8:00-9:00</div>';
echo '<div class="px-4 py-3 border-t">9:00-10:00</div>';
echo '<div class="px-4 py-3 border-t">10:00-11:00</div>';
echo '<div class="px-4 py-3 border-t">11:00-12:00</div>';
echo '<div class="px-4 py-3 border-t">13:00-14:00</div>';
echo '<div class="px-4 py-3 border-t">14:00-15:00</div>';
echo '<div class="px-4 py-3 border-t">15:00-16:00</div>';
echo '</div>';
echo '<div>';
echo '<div class="p-4 font-medium bg-gray-100 w-36">Monday</div>';
echo '<div class="px-4 py-3 border-t">Math</div>';
echo '<div class="px-4 py-3 border-t">Biology</div>';
echo '<div class="px-4 py-3 border-t">History</div>';
echo '<div class="px-4 py-3 border-t">Physics</div>';
echo '<div class="px-4 py-3 border-t">Spanish</div>';
echo '<div class="px-4 py-3 border-t">Latin</div>';
echo '<div class="px-4 py-3 border-t">PE</div>';
echo '</div>';
echo '<div>';
echo '<div class="p-4 font-medium bg-gray-100 w-36">Tuesday</div>';
echo '<div class="px-4 py-3 border-t">English</div>';
echo '<div class="px-4 py-3 border-t">Biology</div>';
echo '<div class="px-4 py-3 border-t">Latin</div>';
echo '<div class="px-4 py-3 border-t">Physics</div>';
echo '<div class="px-4 py-3 border-t">PE</div>';
echo '<div class="px-4 py-3 border-t">PE</div>';
echo '<div class="px-4 py-3 border-t">PE</div>';
echo '</div>';
echo '<div>';
echo '<div class="p-4 font-medium bg-gray-100 w-36">Wednesday</div>';
echo '<div class="px-4 py-3 border-t">English</div>';
echo '<div class="px-4 py-3 border-t">Greek</div>';
echo '<div class="px-4 py-3 border-t">History</div>';
echo '<div class="px-4 py-3 border-t">Physics</div>';
echo '<div class="px-4 py-3 border-t">Biology</div>';
echo '<div class="px-4 py-3 border-t">Latin</div>';
echo '<div class="px-4 py-3 border-t">Engineering</div>';
echo '</div>';
echo '<div>';
echo '<div class="p-4 font-medium bg-gray-100 w-36">Thursday</div>';
echo '<div class="px-4 py-3 border-t">English</div>';
echo '<div class="px-4 py-3 border-t">Greek</div>';
echo '<div class="px-4 py-3 border-t">History</div>';
echo '<div class="px-4 py-3 border-t">Physics</div>';
echo '<div class="px-4 py-3 border-t">Biology</div>';
echo '<div class="px-4 py-3 border-t">PE</div>';
echo '<div class="px-4 py-3 border-t">Physics</div>';
echo '</div>';
echo '<div>';
echo '<div class="p-4 font-medium bg-gray-100 w-36">Friday</div>';
echo '<div class="px-4 py-3 border-t">Engineering</div>';
echo '<div class="px-4 py-3 border-t">Engineering</div>';
echo '<div class="px-4 py-3 border-t">CS</div>';
echo '<div class="px-4 py-3 border-t">History</div>';
echo '<div class="px-4 py-3 border-t">Physics</div>';
echo '<div class="px-4 py-3 border-t">Free period</div>';
echo '<div class="px-4 py-3 border-t">Math</div>';
echo '</div>';
echo '<div>';
echo '<div class="p-4 font-medium bg-gray-100 w-36">Saturday</div>';
echo '<div class="px-4 py-3 border-t">Rowing</div>';
echo '<div class="px-4 py-3 border-t">Rowing</div>';
echo '<div class="px-4 py-3 border-t">-</div>';
echo '<div class="px-4 py-3 border-t">-</div>';
echo '<div class="px-4 py-3 border-t">-</div>';
echo '<div class="px-4 py-3 border-t">-</div>';
echo '<div class="px-4 py-3 border-t">-</div>';
echo '</div>';
echo '<div>';
echo '<div class="p-4 font-medium bg-gray-100 w-36">Sunday</div>';
echo '<div class="px-4 py-3 border-t">-</div>';
echo '<div class="px-4 py-3 border-t">-</div>';
echo '<div class="px-4 py-3 border-t">-</div>';
echo '<div class="px-4 py-3 border-t">-</div>';
echo '<div class="px-4 py-3 border-t">-</div>';
echo '<div class="px-4 py-3 border-t">-</div>';
echo '<div class="px-4 py-3 border-t">-</div>';
echo '</div>';
echo '</div>';
echo '</div>';
echo '</div>';
echo '<div class="md:flex space-y-12 md:space-y-0 md:space-x-4 lg:max-w-screen-lg md:max-w-screen-md pt-12 mx-auto">';
echo '<div>';
echo '<h3 class="text-3xl pb-4  font-semibold tracking-tight">Notices:</h3>';
echo '<div class="border shadow-md border-gray-100 rounded-2xl max-w-max">';
echo '<div class="p-4">';
echo '<p class="font-medium">Biology lecture: The structure of plants</p>';
echo '<p>Come to room 355 today at 12:35 for a lecture on the structure of plants</p>';
echo '<p class="text-cyan-500 pt-2">Add to Calendar &rarr;</p>';
echo '</div>';
echo '<div class="p-4">';
echo '<p class="font-medium">Physics lecture: Electrostatics</p>';
echo '<p>Come to room 211 today at 2:35 for a lecture on the structure of atoms</p>';
echo '<p class="text-cyan-500 pt-2">Add to Calendar &rarr;</p>';
echo '</div>';
echo '<div class="p-4">';
echo '<p class="font-medium">History club</p>';
echo '<p>Come to room 111 for history club! We hope to see you there.</p>';
echo '<p class="text-cyan-500 pt-2">Add to Calendar &rarr;</p>';
echo '</div>';
echo '<div class="p-4">';
echo '<p class="font-medium">Social event: Annual Rowing Dinner</p>';
echo '<p>To the rowing crew, sign up to our Annual Rowing Dinner via the email you were sent.</p>';
echo '<p class="text-cyan-500 pt-2">Add to Calendar &rarr;</p>';
echo '</div>';
echo '</div>';
echo '</div>';
echo '<div>';
echo '<h3 class="text-3xl pb-4 font-semibold tracking-tight">Tasks:</h3>';
echo '<div class="bg-white overflow-hidden rounded-xl shadow-md border border-gray-100 max-w-screen-sm w-64">';
echo '<div class="max-w-screen-sm rounded-lg w-auto">';
echo '<h1 id="todo" class="text-xl px-4 py-4 font-semibold">To-Do</h1>';
echo '<div class="p-2"><form name="form" method="post"><input class="appearance-none focus:outline-none focus:border-gray-100 border p-3 w-full rounded-lg" type="text" name="text_box" placeholder="New To-do Item"><button type="submit" class="p-3 text-white bg-cyan-600 hover:bg-cyan-500 rounded-lg w-full mt-2 text-center" id="search-submit" value="submit">Add Item</button>';
echo '</form>';
echo '</div>';
$usernamevar = $_SESSION['user_name'];
if (!file_exists("$usernamevar/todoitems/")) {
    mkdir("$usernamevar/todoitems", 0777, true);
    mkdir("$usernamevar/todoitems/incomplete", 0777, true);
    mkdir("$usernamevar/todoitems/complete", 0777, true);

}
    if(isset($_POST['text_box'])) { //only do file operations when appropriate
        $a = $_POST['text_box'];
        $myFile = "$usernamevar/todoitems/incomplete/" . $a;
        $fh = fopen($myFile, 'a') or die("can't open file");
        fwrite($fh, $a . PHP_EOL);
        fclose($fh);
    }
echo '<p class="bg-amber-100 text-amber-600 text-sm px-4 py-3">To complete</p>';
$path = "$usernamevar/todoitems/incomplete/";

if ($handle = opendir($path)) {
    while (false !== ($file = readdir($handle))) {
        if ('.' === $file) continue;
        if ('..' === $file) continue;

        echo '<div class="p-4 justify-between flex"><div class="inline-flex"><a href="?done=' . $file . '"><svg xmlns="http://www.w3.org/2000/svg" class="text-white border-2 border-sky-600 rounded-full mr-2 h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg></a><p>' . str_replace(".txt","","$file") . '</p><a href="?delete=' . $file . '"></p></div><svg xmlns="http://www.w3.org/2000/svg" class="text-red-600 hover:text-red-500 h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg></a></div>';


    }
    closedir($handle);
}
echo '<p class="bg-emerald-100 text-emerald-600 text-sm px-4 py-3">Completed</p>';
$path = "$usernamevar/todoitems/complete/";

if ($handle = opendir($path)) {
    while (false !== ($file = readdir($handle))) {
        if ('.' === $file) continue;
        if ('..' === $file) continue;
        echo '<div class="p-4 justify-between flex"><div class="inline-flex"><a href="?undo=' . $file . '"><svg xmlns="http://www.w3.org/2000/svg" class="text-white bg-sky-600 rounded-full mr-2 h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg></a><p>' . str_replace(".txt","","$file") . '</p><a href="?deletecomplete=' . $file . '"></p></div><svg xmlns="http://www.w3.org/2000/svg" class="text-red-600 hover:text-red-500 h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg></a></div>';


    }
    closedir($handle);
}
    if (isset($_GET['delete'])) {
        $x = $_GET['delete'];
        $x = str_replace('.','',$x);
        $x = str_replace('~','',$x);
        $x = str_replace('/','',$x);
        $x = str_replace('\\','',$x);
        unlink("$usernamevar/todoitems/incomplete/" . $x);
        echo '<script>window.location.replace("/#todo");</script>';
    }
    if (isset($_GET['deletecomplete'])) {
        unlink("$usernamevar/todoitems/complete/" . $_GET['deletecomplete']);
        echo '<script>window.location.replace("/#todo");</script>';
    }
    if (isset($_GET['done'])) {
        rename("$usernamevar/todoitems/incomplete/" . $_GET['done'], "$usernamevar/todoitems/complete/" . $_GET['done']);
        echo '<script>window.location.replace("/#todo");</script>';
    }
    if (isset($_GET['undo'])) {
        rename("$usernamevar/todoitems/complete/" . $_GET['undo'], "$usernamevar/todoitems/incomplete/" . $_GET['undo']);
        echo '<script>window.location.replace("/#todo");</script>';
    }
echo '</div>';
echo '</div>';
echo '</div>';
echo '</div>';
echo '';
    }

    /**
     * Simple demo-"page" with the login form.
     * In a real application you would probably include an html-template here, but for this extremely simple
     * demo the "echo" statements are totally okay.
     */
    private function showPageLoginForm()
    {
        if ($this->feedback) {
            echo '<div class="p-4 bg-sky-100 text-center text-sky-600 font-medium">' . $this->feedback . '</div>';
        }
        echo '<section class="bg-gray-100 to-cyan-400">';
        echo '<div class="max-w-screen-lg mx-auto">';
        echo '<div class="px-5 py-12 mx-auto">';
        echo '<h1 class="mx-auto text-center text-3xl mb-4 font-extrabold">Sign in to your account</h1>';
        echo '<div class="w-full px-5 py-5 max-w-md mx-auto overflow-hidden bg-white rounded-2xl shadow-xl">';
        echo '<div class="px-6 py-4">';
        echo '';
        echo '<form method="post" action="' . $_SERVER['SCRIPT_NAME'] . '" name="loginform">';
        echo '<div class="w-full block mt-4">';
        echo '<span class="text-gray-700 font-medium text-sm">Username</span>';
        echo '<input id="login_input_username" type="text" name="user_name" required class="block w-full px-4 py-2 mt-2 text-gray-700 border  placeholder-gray-500 bg-white border-gray-300 rounded-lg focus:border-sky-500 focus:outline-none focus:ring-0" type="text" aria-label="Email Address">';
        echo '</div>';
        echo '';
        echo '<label class="w-full block mt-4">';
        echo '<span class="text-gray-700 font-medium text-sm">Password</span>';
        echo '<input id="login_input_password" type="password" name="user_password" required class="block w-full px-4 py-2 mt-2 text-gray-700 border  placeholder-gray-500 bg-white border-gray-300 rounded-lg focus:border-sky-500 focus:outline-none focus:ring-0" type="password" aria-label="Password">';
        echo '</label>';
        echo '';
        echo '<div class="block mt-8 items-center justify-between">';
        echo '<button type="submit"  name="login" value="Log in" class="w-full block px-4 font-medium py-3 leading-5 text-white transition-colors duration-200 transform bg-sky-500 rounded-lg hover:bg-sky-600 focus:outline-none">';
        echo 'Login';
        echo '</button>';
        echo '</div>';
        echo '</div>';
        echo '</div>';
        echo '</section>';
    }

    /**
     * Simple demo-"page" with the registration form.
     * In a real application you would probably include an html-template here, but for this extremely simple
     * demo the "echo" statements are totally okay.
     */
    private function showPageRegistration()
    {
        if ($this->feedback) {
            echo $this->feedback . "<br/><br/>";
        }

        echo '<h2>Registration</h2>';

        echo '<form method="post" action="' . $_SERVER['SCRIPT_NAME'] . '?action=register" name="registerform">';
        echo '<label for="login_input_username">Username (only letters and numbers, 2 to 64 characters)</label>';
        echo '<input id="login_input_username" type="text" pattern="[a-zA-Z0-9]{2,64}" name="user_name" required />';
        echo '<label for="login_input_email">User\'s email</label>';
        echo '<input id="login_input_email" type="email" name="user_email" required />';
        echo '<label for="login_input_password_new">Password (min. 6 characters)</label>';
        echo '<input id="login_input_password_new" class="login_input" type="password" name="user_password_new" pattern=".{6,}" required autocomplete="off" />';
        echo '<label for="login_input_password_repeat">Repeat password</label>';
        echo '<input id="login_input_password_repeat" class="login_input" type="password" name="user_password_repeat" pattern=".{6,}" required autocomplete="off" />';
        echo '<input type="submit" name="register" value="Register" />';
        echo '</form>';

        echo '<a href="' . $_SERVER['SCRIPT_NAME'] . '">Homepage</a>';
    }
}

// run the application
$application = new OneFileLoginApplication();
?>
