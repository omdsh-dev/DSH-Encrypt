/** A failure-isolated serial task queue for document mutations. */
export class OperationQueue {
  #tail: Promise<void> = Promise.resolve()

  /** Run one operation after all earlier operations have settled. */
  run<T>(operation: () => T | Promise<T>): Promise<T> {
    const task = this.#tail.then(operation)
    this.#tail = task.then(
      () => void 0,
      () => void 0,
    )
    return task
  }

  /** Resolve after the current queue tail has settled. */
  idle(): Promise<void> {
    return this.#tail
  }
}
