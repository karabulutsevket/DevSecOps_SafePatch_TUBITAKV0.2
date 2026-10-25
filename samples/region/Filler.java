    // ---- part A ----
    private final Map<String, String> labels = new LinkedHashMap<>();
    private final List<String> history = new ArrayList<>();
    private int limit = 64;

    public DemoService() {
        labels.put("draft", "Draft");
        labels.put("final", "Final");
        labels.put("archived", "Archived");
    }

    public String label(String key) {
        String value = labels.get(normalizeKey(key));
        return value == null ? "Unknown" : value;
    }

    public void setLimit(int limit) {
        if (limit < 1 || limit > 4096) {
            throw new IllegalArgumentException("limit out of range: " + limit);
        }
        this.limit = limit;
    }

    public int getLimit() {
        return limit;
    }

    static String normalizeKey(String key) {
        if (key == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(key.length());
        for (char c : key.trim().toCharArray()) {
            if (Character.isLetterOrDigit(c)) {
                out.append(Character.toLowerCase(c));
            } else if (c == '-' || c == '_' || c == ' ') {
                out.append('-');
            }
        }
        return out.toString();
    }

    public List<String> splitCsvLine(String line) {
        List<String> cells = new ArrayList<>();
        if (line == null || line.isEmpty()) {
            return cells;
        }
        StringBuilder cell = new StringBuilder();
        boolean quoted = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"') {
                if (quoted && i + 1 < line.length() && line.charAt(i + 1) == '"') {
                    cell.append('"');
                    i++;
                } else {
                    quoted = !quoted;
                }
            } else if (c == ',' && !quoted) {
                cells.add(cell.toString());
                cell.setLength(0);
            } else {
                cell.append(c);
            }
        }
        cells.add(cell.toString());
        return cells;
    }

    public String formatTable(List<List<String>> rows) {
        int columns = 0;
        for (List<String> row : rows) {
            columns = Math.max(columns, row.size());
        }
        int[] widths = new int[columns];
        for (List<String> row : rows) {
            for (int i = 0; i < row.size(); i++) {
                widths[i] = Math.max(widths[i], row.get(i).length());
            }
        }
        StringBuilder out = new StringBuilder();
        for (List<String> row : rows) {
            for (int i = 0; i < columns; i++) {
                String value = i < row.size() ? row.get(i) : "";
                out.append(value);
                for (int pad = value.length(); pad < widths[i] + 2; pad++) {
                    out.append(' ');
                }
            }
            out.append('\n');
        }
        return out.toString();
    }

    // ---- part B ----
    public long checksum(String text) {
        long hash = 1125899906842597L;
        for (int i = 0; i < text.length(); i++) {
            hash = 31 * hash + text.charAt(i);
        }
        return hash;
    }

    public String abbreviate(String text, int width) {
        Objects.requireNonNull(text, "text");
        if (width < 4) {
            throw new IllegalArgumentException("width too small");
        }
        if (text.length() <= width) {
            return text;
        }
        return text.substring(0, width - 3) + "...";
    }

    public Map<String, Integer> wordCounts(String text) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (String word : text.toLowerCase(Locale.ROOT).split("[^a-z0-9]+")) {
            if (!word.isEmpty()) {
                counts.merge(word, 1, Integer::sum);
            }
        }
        return counts;
    }

    public List<String> topWords(String text, int count) {
        List<Map.Entry<String, Integer>> entries = new ArrayList<>(wordCounts(text).entrySet());
        entries.sort((a, b) -> b.getValue().equals(a.getValue()) ? a.getKey().compareTo(b.getKey()) : b.getValue() - a.getValue());
        List<String> words = new ArrayList<>();
        for (int i = 0; i < Math.min(count, entries.size()); i++) {
            words.add(entries.get(i).getKey());
        }
        return words;
    }

    public void remember(String event) {
        history.add(event);
        while (history.size() > limit) {
            history.remove(0);
        }
    }

    public List<String> recent(int count) {
        int from = Math.max(0, history.size() - count);
        return Collections.unmodifiableList(new ArrayList<>(history.subList(from, history.size())));
    }

    public String describe() {
        return "DemoService[labels=" + labels.size() + ", history=" + history.size() + ", limit=" + limit + "]";
    }
