export function getItem<T>(key: string): T | null {
    try {
        const item = localStorage.getItem(key);
        return item ? JSON.parse(item) as T : null;
    } catch (error) {
        throw new Error(`Error getting ${key} item from localStorage: ${error}`);
        return null;
    }
}

export function setItem<T>(key: string, value: T) {
    try {
        localStorage.setItem(key, JSON.stringify(value));
    } catch (error) {
        throw new Error(`Error setting ${key} item in localStorage: ${error}`);
    }
}