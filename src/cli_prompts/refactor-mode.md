# ⚡ Refactor / Limpieza de Deuda Técnica
#
# Modo enfocado exclusivamente en eliminar deuda técnica sin cambiar comportamiento.

## MODO REFACTOR SEGURO ACTIVADO

**REGLA DORADA**: El comportamiento EXTERNO no cambia. Solo la estructura INTERNA.

### Principios del Refactor Seguro:
1. **Test Coverage**: Nunca toques código sin tests que lo cubran
2. **Commits Pequeños**: Cada refactor atómico es un commit separado
3. **Green Bar Siempre**: Después de cada paso, los tests pasan
4. **No New Features**: Durante refactor, NO agregues funcionalidad nueva

### Técnicas Comunes (con nombres):

#### 1. Composing Methods
- **Extract Method**: Fragmento de código → método con nombre descriptivo
- **Inline Method**: Cuerpo del método en vez de llamada (cuando el nombre no aporta)
- **Extract Variable**: Expresión compleja → variable con nombre
- **Split Temporary Variable**: Variable usada para múltiples cosas → múltiples variables
- **Remove Assignments to Parameters**: Parámetros no se modifican

#### 2. Moving Features Between Objects
- **Move Method**: Método está en la clase equivocada → muévelo
- **Move Field**: Atributo pertenece a otra clase → muévelo
- **Extract Class**: Una clase hace demasiado → parte en dos
- **Inline Class**: Una clase no hace casi nada → fusílala

#### 3. Organizing Data
- **Self Encapsulate Field**: Acceso directo a field → via getter/setter
- **Replace Data Value with Object**: Dato simple con comportamiento → su propia clase
- **Change Reference to Value**: Objeto referenciado → objeto valor (inmutable)
- **Replace Array with Object**: Array con diferentes elementos → objeto con campos nombrado

#### 4. Simplifying Conditionals
- **Decompose Conditional**: If complejo → métodos con nombre (is_something())
- **Consolidate Conditional Expression**: Múltiples checks con mismo resultado → uno solo
- **Consolidate Duplicate Conditional Fragments**: Código igual en todas las ramas → afuera
- **Replace Nested Conditional with Guard Clauses**: Return early en vez de anidamiento
- **Introduce Null Object**: Checks por null → Null Object pattern

#### 5. Making Method Calls Simpler
- **Rename Method**: Nombre poco claro → mejor nombre
- **Add Parameter**: Método necesita más información
- **Remove Parameter**: Parámetro no se usa
- **Separate Query from Modifier**: Método que devuelve y modifica → dos métodos separados
- **Parameterize Method**: Métodos similares con diferentes valores → uno solo con parámetro
- **Replace Parameter with Explicit Methods**: Parámetro decide comportamiento → métodos separados

### Checklist Antes de Cada Refactor:
- [ ] ¿Hay tests que cubran este código?
- [ ] ¿Los tests están verdes AHORA?
- [ ] ¿Entiendo QUÉ hace el código?
- [ ] ¿Entiendo POR QUÉ está escrito así?

### Después de Cada Refactor:
- [ ] `pytest` - todo verde
- [ ] `git diff` - solo lo esperado cambió
- [ ] `git add -p` / `git commit` - commit atómico

## FIN DEL PROMPT DE REFACTOR
