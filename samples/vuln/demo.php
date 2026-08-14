<?php
$cmd = $_GET['cmd'];
eval($cmd);
exec($cmd);
mysqli_query($conn, "SELECT * FROM t WHERE id = " . $cmd);
$password = "hunter2";
unserialize($input);
setcookie("sid", $token);
?>