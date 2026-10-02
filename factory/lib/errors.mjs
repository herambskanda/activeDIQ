/** A failure with a user-readable message. The CLI prints it and exits 1; the board maps `status` to HTTP. */
export class FactoryError extends Error {
  /**
   * @param {string} message
   * @param {number} [status] HTTP status used by the board (default 400)
   */
  constructor(message, status = 400) {
    super(message);
    this.name = 'FactoryError';
    this.status = status;
  }
}

/** A referenced entity does not exist. */
export class NotFoundError extends FactoryError {
  /** @param {string} message */
  constructor(message) {
    super(message, 404);
    this.name = 'NotFoundError';
  }
}

/** Bad command line. The CLI prints it with a usage hint and exits 2. */
export class UsageError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = 'UsageError';
  }
}
