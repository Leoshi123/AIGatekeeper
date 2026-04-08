
/**
 * Recursive Generics & Complex Types Stress Test
 */
type Recursive<T, U> = T extends U ? T : { a: Recursive<T, U> };
type ComplexType<T> = Recursive<T, any>;

async function complexGenericProcess<T extends ComplexType<any>>(input: T) {
    console.log("Processing complex generic");
    // CRITICAL: innerHTML in complex type context
    const element = document.getElementById('app');
    if (element) {
        element.innerHTML = `<div>${input}</div>`;
    }
}
