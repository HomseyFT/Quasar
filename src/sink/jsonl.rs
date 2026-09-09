//! The durable event log.
//!
//! One JSON object per line, appended, never rewritten. This is the record of
//! what happened and the input `quasar learn` reads; the record itself is
//! defined in [`super::record`], because `quasar top` serves the same value.

use std::{
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    path::Path,
};

use anyhow::{Context, Result};

use super::record::Record;

pub struct JsonlSink {
    writer: BufWriter<File>,
}

impl JsonlSink {
    pub fn create(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("opening {}", path.display()))?;

        Ok(Self {
            writer: BufWriter::new(file),
        })
    }

    pub fn write(&mut self, record: &Record) -> Result<()> {
        serde_json::to_writer(&mut self.writer, record).context("serialising a log record")?;
        self.writer.write_all(b"\n").context("writing the log")?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush().context("flushing the log")
    }
}
