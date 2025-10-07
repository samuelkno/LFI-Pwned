<?php
// welcome.php - archivo de ejemplo para Nivel 6
// Contiene código legible que los alumnos deberán obtener usando wrappers.

function saludar($nombre) {
    echo "Hola, " . htmlspecialchars($nombre) . "! Bienvenido al Nivel 6.\n";
}

$autor = "Profesor Lab";
$descripcion = "Este archivo demuestra lectura de código con php://filter y phar://";

saludar("Estudiante");
// imprimimos una línea distintiva para detección automática en el lab
echo "\n/* WELCOME_FILE_LEVEL6 */\n";
?>
