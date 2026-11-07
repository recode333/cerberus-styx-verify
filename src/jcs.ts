// RFC 8785 (JCS) canonical JSON for parsed JSON values (output of
// JSON.parse). JSON.stringify realizes RFC 8785 primitive serialization
// exactly: strings per section 3.2.2.2 and numbers per section 3.2.2.3
// (ECMAScript shortest round-trip). Member names sort as UTF-16 code-unit
// sequences (section 3.2.3), the default JS string sort. Anything that is not
// plain JSON (undefined members, non-finite numbers, other types) is refused.

function esObjetoPlano(valor: unknown): valor is Record<string, unknown> {
  return typeof valor === "object" && valor !== null && !Array.isArray(valor);
}

// Streams canonical fragments to the emitter so measurement can abort early
// without materializing the full serialization.
export function serializarEnFragmentos(valor: unknown, emitir: (fragmento: string) => void): void {
  if (valor === null || typeof valor === "boolean" || typeof valor === "string") {
    emitir(JSON.stringify(valor));
    return;
  }
  if (typeof valor === "number") {
    if (!Number.isFinite(valor)) {
      throw new TypeError("valor numérico no finito no es canonicalizable (RFC 8785)");
    }
    emitir(JSON.stringify(valor));
    return;
  }
  if (Array.isArray(valor)) {
    emitir("[");
    for (let i = 0; i < valor.length; i += 1) {
      if (i > 0) {
        emitir(",");
      }
      serializarEnFragmentos(valor[i], emitir);
    }
    emitir("]");
    return;
  }
  if (esObjetoPlano(valor)) {
    // Parse output never contains undefined members; refuse defensively
    // instead of transforming the value (RFC 8785 "no transformation").
    emitir("{");
    const claves = Object.keys(valor).sort();
    for (let i = 0; i < claves.length; i += 1) {
      const clave = claves[i] as string;
      const miembro = valor[clave];
      if (miembro === undefined) {
        throw new TypeError("miembro undefined no es canonicalizable (RFC 8785)");
      }
      if (i > 0) {
        emitir(",");
      }
      emitir(JSON.stringify(clave));
      emitir(":");
      serializarEnFragmentos(miembro, emitir);
    }
    emitir("}");
    return;
  }
  throw new TypeError("valor no canonicalizable (RFC 8785)");
}

export function serializarJcs(valor: unknown): string {
  const fragmentos: string[] = [];
  serializarEnFragmentos(valor, (fragmento) => {
    fragmentos.push(fragmento);
  });
  return fragmentos.join("");
}

