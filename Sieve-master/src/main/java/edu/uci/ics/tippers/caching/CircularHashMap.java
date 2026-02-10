package edu.uci.ics.tippers.caching;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Arrays;

public class CircularHashMap<K, V> {
    private static final int DEFAULT_CAPACITY = 10;

    private Object[] keys;
    private Object[] values;
    private int size;
    private int capacity;

    public CircularHashMap() {
        this(DEFAULT_CAPACITY);
    }

    public CircularHashMap(int capacity) {
        this.capacity = capacity;
        this.keys = new Object[capacity];
        this.values = new Object[capacity];
        this.size = 0;
    }

    private int getIndex(K key) {
        return Math.abs(key.hashCode()) % capacity;
    }

    public void put(K key, V value) {
        int index = getIndex(key);

        // Check if key already exists, update the value
        for (int i = 0; i < size; i++) {
            if (keys[i].equals(key)) {
                values[i] = value;
                return;
            }
        }

        // If the capacity is reached, overwrite the oldest entry
        if (size == capacity) {
            // Overwrite the oldest entry
            int oldestIndex = size % capacity;
            keys[oldestIndex] = key;
            values[oldestIndex] = value;
        } else {
            // Add a new entry
            keys[size] = key;
            values[size] = value;
            size++;
        }
    }

    public V get(K key) {
        int index = getIndex(key);
        for (int i = 0; i < size; i++) {
            if (keys[i].equals(key)) {
                return (V) values[i];
            }
        }
        return null; // Key not found
    }

    @Override
    public String toString() {
        return "CircularHashMap{" +
                "keys=" + Arrays.toString(keys) +
                ", values=" + Arrays.toString(values) +
                '}';
    }

    public static void main(String[] args) {
        CircularHashMap<String, Timestamp> circularHashMap = new CircularHashMap<>(3);

        long millis = Instant.now().toEpochMilli();
        circularHashMap.put("One", new Timestamp(millis));
        circularHashMap.put("Two", new Timestamp(millis+2));
        circularHashMap.put("Three", new Timestamp(millis+3));

        System.out.println(circularHashMap); // Output: CircularHashMap{keys=[Three, Two, One], values=[3, 2, 1]}

        circularHashMap.put("Four", new Timestamp(millis+4));

        System.out.println(circularHashMap); // Output: CircularHashMap{keys=[Four, Two, One], values=[4, 2, 1]}
    }
}
