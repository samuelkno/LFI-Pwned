<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $num1 = $_POST['num1'];
    $num2 = $_POST['num2'];
    $suma = $num1 + $num2;

    echo "<h2>Resultado:</h2>";
    echo "<p>La suma de $num1 y $num2 es <strong>$suma</strong></p>";
}
?>

<form method="post" action="">
    <label for="num1">Ingrese el primer número:</label><br>
    <input type="number" name="num1" id="num1" required><br><br>

    <label for="num2">Ingrese el segundo número:</label><br>
    <input type="number" name="num2" id="num2" required><br><br>

    <input type="submit" value="Sumar">
</form>
