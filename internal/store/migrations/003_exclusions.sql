ALTER TABLE optouts RENAME TO exclusions;
ALTER TABLE exclusions RENAME COLUMN contact TO note;
