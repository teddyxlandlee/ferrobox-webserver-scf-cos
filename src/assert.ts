export function error(message: string): never {
    throw new Error(message)
}

export function assert(condition: boolean, message: string): void {
    if (!condition) error(message)
}
