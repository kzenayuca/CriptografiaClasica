/*
 * cripto.cpp  --  Criptografia clasica en C++17
 *   1) Cifrado/descifrado por PERMUTACION DE SERIES (transposicion por bloques)
 *   2) DESCIFRADO PLAYFAIR (matriz 5x5, I/J unificadas)
 *
 * Compilar:  g++ -std=c++17 -Wall -Wextra -O2 cripto.cpp -o cripto
 */
#include <algorithm>
#include <array>
#include <cctype>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace cripto {

// ---------------------------------------------------------------------------
// Utilidades comunes
// ---------------------------------------------------------------------------

/// Sanitiza: convierte a mayusculas y conserva solo letras A-Z (ASCII).
/// Si unirIJ es true, sustituye J por I (requisito de Playfair 5x5).
std::string sanitizar(const std::string& texto, bool unirIJ = false) {
    std::string limpio;
    limpio.reserve(texto.size());
    for (unsigned char c : texto) {
        char u = static_cast<char>(std::toupper(c));
        if (u < 'A' || u > 'Z') continue;      // descarta espacios, digitos, signos, no-ASCII
        if (unirIJ && u == 'J') u = 'I';
        limpio.push_back(u);
    }
    return limpio;
}

// ---------------------------------------------------------------------------
// PARTE 1: Cifrado por permutacion de series
// ---------------------------------------------------------------------------
// El texto se divide en series (bloques) de n letras, donde n es la longitud
// de la clave. La clave es una permutacion de {1..n}: la letra que queda en
// la posicion i de la serie cifrada es la que estaba en la posicion clave[i].
// Si la ultima serie esta incompleta se rellena con 'X'.

using Clave = std::vector<int>;

/// Valida que la clave sea una permutacion de 1..n.
void validarClave(const Clave& k) {
    if (k.empty()) throw std::invalid_argument("La clave de permutacion esta vacia.");
    std::vector<bool> visto(k.size() + 1, false);
    for (int v : k) {
        if (v < 1 || static_cast<std::size_t>(v) > k.size() || visto[v])
            throw std::invalid_argument("La clave debe ser una permutacion de 1..n sin repetidos.");
        visto[v] = true;
    }
}

/// Convierte texto a clave. Admite:
///  - numeros separados por espacios/comas/nada ("3 1 4 2", "3,1,4,2")
///  - una palabra clave (rango alfabetico; empates resueltos de izquierda a derecha)
Clave parsearClave(const std::string& entrada) {
    bool hayLetras = std::any_of(entrada.begin(), entrada.end(),
                                 [](unsigned char c) { return std::isalpha(c) != 0; });
    Clave k;
    if (!hayLetras) {
        std::string tmp = entrada;
        std::replace(tmp.begin(), tmp.end(), ',', ' ');
        std::istringstream iss(tmp);
        int v;
        while (iss >> v) k.push_back(v);
        // Caso "3142" pegado: cada digito es una posicion (solo si n<=9)
        if (k.size() == 1 && k[0] > 9) {
            std::string d = std::to_string(k[0]);
            k.clear();
            for (char c : d) k.push_back(c - '0');
        }
    } else {
        std::string p = sanitizar(entrada);
        std::vector<std::size_t> idx(p.size());
        for (std::size_t i = 0; i < idx.size(); ++i) idx[i] = i;
        std::stable_sort(idx.begin(), idx.end(),
                         [&](std::size_t a, std::size_t b) { return p[a] < p[b]; });
        k.assign(p.size(), 0);
        for (std::size_t r = 0; r < idx.size(); ++r) k[idx[r]] = static_cast<int>(r) + 1;
    }
    validarClave(k);
    return k;
}

/// Cifra por permutacion de series. 'relleno' recibe el numero de X anadidas.
std::string cifrarPermutacion(const std::string& texto, const Clave& k, std::size_t* relleno = nullptr) {
    validarClave(k);
    std::string t = sanitizar(texto);
    const std::size_t n = k.size();
    std::size_t pad = (n - t.size() % n) % n;
    t.append(pad, 'X');                         // completa la ultima serie
    if (relleno) *relleno = pad;

    std::string out(t.size(), ' ');
    for (std::size_t b = 0; b < t.size(); b += n)
        for (std::size_t i = 0; i < n; ++i)
            out[b + i] = t[b + static_cast<std::size_t>(k[i] - 1)];
    return out;
}

/// Descifra aplicando la permutacion inversa. Si quitarRelleno, elimina X finales.
std::string descifrarPermutacion(const std::string& cifrado, const Clave& k, bool quitarRelleno = false) {
    validarClave(k);
    std::string c = sanitizar(cifrado);
    const std::size_t n = k.size();
    if (c.size() % n != 0)
        throw std::invalid_argument("La longitud del criptograma no es multiplo de la clave.");

    std::string out(c.size(), ' ');
    for (std::size_t b = 0; b < c.size(); b += n)
        for (std::size_t i = 0; i < n; ++i)
            out[b + static_cast<std::size_t>(k[i] - 1)] = c[b + i];   // inversa
    if (quitarRelleno)
        while (!out.empty() && out.back() == 'X') out.pop_back();
    return out;
}

// ---------------------------------------------------------------------------
// PARTE 2: Descifrado Playfair
// ---------------------------------------------------------------------------

using Matriz = std::array<std::array<char, 5>, 5>;

/// Construye la matriz 5x5 a partir de la clave (sin repetidos, I/J unidas).
Matriz construirMatriz(const std::string& clave) {
    std::string seq = sanitizar(clave, true);
    seq += "ABCDEFGHIKLMNOPQRSTUVWXYZ";          // alfabeto de 25 letras (sin J)
    std::array<bool, 26> usada{};
    Matriz m{};
    int pos = 0;
    for (char c : seq) {
        if (usada[c - 'A']) continue;
        usada[c - 'A'] = true;
        m[pos / 5][pos % 5] = c;
        ++pos;
    }
    return m;
}

/// Localiza una letra (fila, columna) en la matriz.
std::pair<int, int> buscar(const Matriz& m, char c) {
    for (int f = 0; f < 5; ++f)
        for (int col = 0; col < 5; ++col)
            if (m[f][col] == c) return {f, col};
    throw std::logic_error("Letra fuera de la matriz.");
}

/// Descifra un digrama segun las 3 reglas de Playfair.
std::string descifrarDigrama(const Matriz& m, char a, char b) {
    auto pos1 = buscar(m, a);
    auto pos2 = buscar(m, b);

    int f1 = pos1.first;
    int c1 = pos1.second;

    int f2 = pos2.first;
    int c2 = pos2.second;

    if (f1 == f2) {
        // Regla 1: misma fila -> letra a la izquierda
        c1 = (c1 + 4) % 5;
        c2 = (c2 + 4) % 5;
    } else if (c1 == c2) {
        // Regla 2: misma columna -> letra arriba
        f1 = (f1 + 4) % 5;
        f2 = (f2 + 4) % 5;
    } else {
        // Regla 3: rectángulo -> intercambiar columnas
        int temp = c1;
        c1 = c2;
        c2 = temp;
    }

    return std::string(1, m[f1][c1]) + m[f2][c2];
}

/// Elimina las 'X' de relleno:
///  - 'X' insertada entre dos letras iguales (segunda posicion de un digrama: BALXLOON)
///  - 'X' final que completa la longitud par.
/// Nota: es heuristica; una 'X' genuina en esos contextos es indistinguible.
std::string quitarRellenoX(const std::string& t) {
    std::string out;
    for (std::size_t i = 0; i < t.size(); ++i) {
        bool intermedia = t[i] == 'X' && i % 2 == 1 && i > 0 && i + 1 < t.size() && t[i - 1] == t[i + 1];
        if (!intermedia) out.push_back(t[i]);
    }
    if (!out.empty() && out.back() == 'X') out.pop_back();
    return out;
}

/// Descifra un criptograma Playfair completo.
std::string descifrarPlayfair(const std::string& cifrado, const std::string& clave, bool quitarX = true) {
    Matriz m = construirMatriz(clave);
    std::string c = sanitizar(cifrado, true);
    if (c.empty() || c.size() % 2 != 0)
        throw std::invalid_argument("El criptograma Playfair debe tener longitud par y no vacia.");

    std::string claro;
    for (std::size_t i = 0; i < c.size(); i += 2) {
        if (c[i] == c[i + 1])
            throw std::invalid_argument("Digrama con letras iguales: no es un criptograma Playfair valido.");
        claro += descifrarDigrama(m, c[i], c[i + 1]);
    }
    return quitarX ? quitarRellenoX(claro) : claro;
}

/// Imprime la matriz 5x5.
void imprimirMatriz(const Matriz& m) {
    for (const auto& fila : m) {
        for (char c : fila) std::cout << c << ' ';
        std::cout << '\n';
    }
}

}  // namespace cripto

// ---------------------------------------------------------------------------
// Interfaz: pruebas predefinidas y menu interactivo
// ---------------------------------------------------------------------------

static void pruebasPredefinidas() {
    using namespace cripto;
    std::cout << "=== Pruebas predefinidas ===\n\n";

    // --- Permutacion de series ---
    std::cout << "[Permutacion de series]  clave = 3 1 4 2\n";
    Clave k = parsearClave("3 1 4 2");
    std::size_t pad = 0;
    std::string c = cifrarPermutacion("ATAQUE AL AMANECER", k, &pad);
    std::cout << "  Claro      : ATAQUEALAMANECER\n";
    std::cout << "  Cifrado    : " << c << "  (relleno: " << pad << ")\n";
    std::cout << "  Descifrado : " << descifrarPermutacion(c, k, true) << "\n";

    Clave kp = parsearClave("LUNA");             // palabra clave -> permutacion
    std::cout << "  Clave 'LUNA' -> ";
    for (int v : kp) std::cout << v << ' ';
    std::string c2 = cifrarPermutacion("HOLA MUNDO", kp, &pad);
    std::cout << "\n  'HOLA MUNDO' -> " << c2 << "  (relleno: " << pad << ") -> "
              << descifrarPermutacion(c2, kp, true) << "\n\n";

    // --- Playfair ---
    std::cout << "[Playfair]  clave = PLAYFAIR EXAMPLE\n";
    imprimirMatriz(construirMatriz("PLAYFAIR EXAMPLE"));
    std::string cp = "BMODZBXDNABEKUDMUIXMMOUVIF";
    std::cout << "  Cifrado        : " << cp << "\n";
    std::cout << "  Sin quitar X   : " << descifrarPlayfair(cp, "PLAYFAIR EXAMPLE", false) << "\n";
    std::cout << "  Con quitar X   : " << descifrarPlayfair(cp, "PLAYFAIR EXAMPLE", true) << "\n\n";
}

static void menuInteractivo() {
    using namespace cripto;
    std::string op, a, b;
    while (true) {
        std::cout << "--- Menu ---\n"
                     "1) Cifrar permutacion de series\n"
                     "2) Descifrar permutacion de series\n"
                     "3) Descifrar Playfair\n"
                     "0) Salir\n> ";
        if (!std::getline(std::cin, op) || op == "0") break;
        try {
            if (op == "1" || op == "2") {
                std::cout << "Clave (numeros o palabra): ";
                if (!std::getline(std::cin, a)) break;
                std::cout << "Texto: ";
                if (!std::getline(std::cin, b)) break;
                Clave k = parsearClave(a);
                if (op == "1") {
                    std::size_t pad = 0;
                    std::string r = cifrarPermutacion(b, k, &pad);
                    std::cout << "Cifrado: " << r << "  (relleno X: " << pad << ")\n";
                } else {
                    std::cout << "Descifrado: " << descifrarPermutacion(b, k, true) << "\n";
                }
            } else if (op == "3") {
                std::cout << "Clave: ";
                if (!std::getline(std::cin, a)) break;
                std::cout << "Criptograma: ";
                if (!std::getline(std::cin, b)) break;
                std::cout << "Matriz:\n";
                imprimirMatriz(construirMatriz(a));
                std::cout << "Descifrado: " << descifrarPlayfair(b, a) << "\n";
            } else {
                std::cout << "Opcion no valida.\n";
            }
        } catch (const std::exception& e) {
            std::cout << "Error: " << e.what() << "\n";
        }
        std::cout << '\n';
    }
}

int main() {
    pruebasPredefinidas();
    menuInteractivo();
    return 0;
}