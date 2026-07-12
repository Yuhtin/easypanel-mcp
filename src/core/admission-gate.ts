export class AdmissionGateError extends Error {
  readonly code = "SERVER_BUSY";

  constructor() {
    super("SERVER_BUSY");
    this.name = "AdmissionGateError";
  }
}

/** A fail-fast concurrency gate. It never queues callers or captures their inputs. */
export class AdmissionGate {
  readonly #maximum: number;
  #active = 0;

  constructor(maximum = 16) {
    if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 256) {
      throw new AdmissionGateError();
    }
    this.#maximum = maximum;
  }

  enter(): () => void {
    if (this.#active >= this.#maximum) throw new AdmissionGateError();
    this.#active += 1;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.#active -= 1;
    };
  }
}
