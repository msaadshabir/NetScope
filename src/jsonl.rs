use serde::Serialize;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

#[derive(Debug)]
pub struct JsonlSink {
    writer: BufWriter<File>,
}

impl JsonlSink {
    pub fn new(path: &Path) -> Result<Self, std::io::Error> {
        let file = File::create(path)?;
        Ok(JsonlSink {
            writer: BufWriter::new(file),
        })
    }

    pub fn write<T: Serialize>(&mut self, record: &T) -> Result<(), std::io::Error> {
        let line = serde_json::to_string(record)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        writeln!(self.writer, "{}", line)
    }

    pub fn flush(&mut self) -> Result<(), std::io::Error> {
        self.writer.flush()
    }
}
