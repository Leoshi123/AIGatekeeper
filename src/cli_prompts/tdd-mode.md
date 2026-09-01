# 🔬 TDD Mode - Test Driven Development
#
# Activa este modo para estricto ciclo TDD: RED → GREEN → REFACTOR

## MODO TDD ESTRICTO ACTIVADO

Seguirás el ciclo TDD de manera RIGUROSA. Sin excepciones.

### El Ciclo Sagrado:
```
1. 🔴 RED: Escribe el test PRIMERO. Debe fallar.
2. 🟢 GREEN: Escribe el código MÍNIMO necesario para que pase.
3. 🟡 REFACTOR: Limpia el código SIN romper los tests.
```

### Reglas Inquebrantables:
1. **NUNCA** escribas código de producción sin un test que falle primero
2. **NUNCA** escribas más código del necesario para pasar el test actual
3. **NUNCA** hagas refactor sin tests verdes
4. **NUNCA** saltes el paso REFACTOR
5. **Un assert por test** (idealmente)

### Workflow Paso a Paso:

#### Paso 1 - Entender el Requerimiento
- Pregunta hasta que el requerimiento sea medible
- Identifica casos borde: null, empty, max, negativos, tipos incorrectos

#### Paso 2 - Escribir el Primer Test
```bash
# Primero crea el archivo de test
tests/test_<feature>.py

# Ejecuta y confirma que está ROJO
pytest tests/test_<feature>.py -v
```

#### Paso 3 - Código Mínimo para GREEN
- El código más feo posible que haga pasar el test
- Nada de optimizaciones, nada de patrones
- Solo: ¿pasa el test?

#### Paso 4 - REFACTOR
Ahora SÍ mejora el código:
- Nombres apropiados
- Extraer métodos/clases
- Remover duplicación
- Aplicar patrones si corresponde
- **Después de cada cambio: pytest**

#### Paso 5 - Siguiente Test
Repite el ciclo para el siguiente caso.

### Convención de Nombres para Tests:
```python
def test_<que_esta_probando>_<resultado_esperado>():
    """Given <contexto> When <accion> Then <resultado>"""
    pass
```

Ejemplos:
- `test_deposit_positive_amount_increases_balance`
- `test_withdraw_more_than_balance_raises_error`
- `test_empty_list_returns_zero_length`

### Usa AIGatekeeper para Validar:
```bash
# En cada paso del ciclo
pytest tests/test_tufuncion.py -v

# Escanea el código de tests también
aigatekeeper shield scan tests/test_<feature>.py
```

## FIN DEL PROMPT TDD
