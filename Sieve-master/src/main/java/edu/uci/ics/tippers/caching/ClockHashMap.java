package edu.uci.ics.tippers.caching;

import edu.uci.ics.tippers.model.guard.GuardExp;

import java.util.Arrays;

public class ClockHashMap<K, V> {
    private static final int DEFAULT_CAPACITY = 10;

    private Entry<K, V>[] entries;
    public int size;
    private int capacity;
    private int hand; // Clock hand position

    public ClockHashMap() {
        this(DEFAULT_CAPACITY);
    }

    public ClockHashMap(int capacity) {
        this.capacity = capacity;
        this.entries = new Entry[capacity];
        this.size = 0;
        this.hand = 0;
    }

    public int getIndex(K key) {
        for (int i = 0; i < size; i++) {
            Entry<K, V> entry = entries[i];
            if (entry.key.equals(key)) {
                return i;
            }
        }
        return 0;
    }

    public void put(K key, V value) {
        int index = getIndex(key);

        // Check if key already exists, update the value
        for (int i = 0; i < size; i++) {
            Entry<K, V> entry = entries[i];
            if (entry.key.equals(key)) {
                entry.value = value;
                entry.referenced = true;
                return;
            }
        }

        // If the capacity is reached, replace entries using the Clock algorithm
        if (size == capacity) {
            while (true) {
                Entry<K, V> currentEntry = entries[hand];
                if (currentEntry.referenced) {
                    currentEntry.referenced = false; // Reset the "use" bit
                } else {
                    // Replace the current entry
                    currentEntry.key = key;
                    currentEntry.value = value;
                    currentEntry.referenced = true;
                    hand = (hand + 1) % capacity; // Move the hand
                    return;
                }
                hand = (hand + 1) % capacity; // Move the hand
            }
        } else {
            // Add a new entry
            entries[size] = new Entry<>(key, value, true);
            size++;
        }
    }

    public GuardExp get(K key) {
        int index = getIndex(key);
        for (int i = 0; i < size; i++) {
            Entry<K, V> entry = entries[i];
            if (entry.key.equals(key)) {
                entry.referenced = true; // Set the "use" bit
                return (GuardExp) entry.value;
            }
        }
        return null; // Key not found
    }

    public void update(K key) {
        for (int i = 0; i < size; i++) {
            Entry<K, V> entry = entries[i];
            if (entry.key.equals(key)) {
                entry.referenced = true; // Set the "use" bit
                return;
            }
        }
    }

    public void findAndUpdate(K key, V value) {
        int index = getIndex(key);
        for (int i = 0; i < size; i++) {
            Entry<K, V> entry = entries[i];
            if (entry.key.equals(key)) {
                entry.value = value;
                entry.referenced = true; // Set the "use" bit
                return;
            }
        }
        put(key, value); // If key not found, add a new entry
    }

    @Override
    public String toString() {
        return "ClockHashMap{" +
                "entries=" + Arrays.toString(entries) +
                '}';
    }

    private static class Entry<K, V> {
        private K key;
        private V value;
        private boolean referenced;

        public Entry(K key, V value, boolean referenced) {
            this.key = key;
            this.value = value;
            this.referenced = referenced;
        }

        @Override
        public String toString() {
            return "Entry{" +
                    "key=" + key +
                    ", value=" + value +
                    ", referenced=" + referenced +
                    '}';
        }
    }

    public static void main(String[] args) {
        ClockHashMap<String, Integer> clockHashMap = new ClockHashMap<>(3);

        clockHashMap.put("One", 1);
        clockHashMap.put("Two", 2);
        clockHashMap.put("Three", 3);

        System.out.println(clockHashMap);

        clockHashMap.put("Four", 4);

        System.out.println(clockHashMap);

        System.out.println("Value for key 'Two': " + clockHashMap.get("Two"));

        System.out.println(clockHashMap);

        clockHashMap.put("Five", 5);

        System.out.println(clockHashMap);

        clockHashMap.put("Six", 6);

        System.out.println(clockHashMap);

        clockHashMap.put("One", 1);
        clockHashMap.put("Two", 2);

        System.out.println(clockHashMap);

        // Testing update()
        clockHashMap.update("One");

        // Testing findAndUpdate()
        clockHashMap.findAndUpdate("Seven", 7);

        System.out.println(clockHashMap);
    }
}
