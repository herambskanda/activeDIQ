// Deliberate violations. `make ci-proof` lints this file with --no-ignore and requires failure.
export const x: any = 1;
eval("1");
console.log(x);
document.body.innerHTML = "<b>raw</b>";
