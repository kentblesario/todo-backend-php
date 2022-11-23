<?php
// Headers
//RewriteRule ^create/task/([^/]*)$ /create.php?item=$1 [L]
header('Access-Control-Allow-Origin: *');
header('Content-Type: application/json');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Access-Control-Allow-Headers,Content-Type,Access-Control-Allow-Methods, Authorization, X-Requested-With');

include_once 'config/Database.php';
include_once 'models/Todo.php';

// Instantiate DB & connect
$database = new Database();
$db = $database->connect();
$output = array();
// Instantiate Todo object
$todo = new Todo($db);

// Get raw posted data
$data = json_decode(file_get_contents("php://input"));
// echo json_encode($data);
// Create Task
$secret = 'secret';
$headers = array('alg'=>'HS256','typ'=>'JWT');
$payload = array('email'=>$data->email, 'admin'=>true,'password'=>$data->password, 'exp'=>(time() + 86400));
//86400 secs in a day


if ($todo->auth($header,$payload,$secret)) {
    $output['status'] = 200;
    $output['message'] = "Authenticated";
    $output['jwt'] = $todo->auth($header,$payload,$secret);
} else {
    $output['status'] = 204;
    $output['message'] = "Invalid Credentials";
}

// Turn to JSON & output
echo json_encode($output);
