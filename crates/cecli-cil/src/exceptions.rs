//! Exception handling clauses and their small/fat section encodings
//! (`Mono.Cecil.Cil/ExceptionHandler.cs` plus the section logic of
//! `CodeReader.cs`/`CodeWriter.cs`; ECMA-335 II §25.4.6).

use cecli_core::{Error, Result, Token};

use cecli_core::io::{ByteReader, ByteWriter};

/// The kind of an exception handler (C# `ExceptionHandlerType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExceptionHandlerType {
    /// `catch <type>`; [`ExceptionHandler::catch_type`] carries the token.
    Catch,
    /// A filter block guards the handler.
    Filter,
    /// `finally`.
    Finally,
    /// `fault`.
    Fault,
}

impl ExceptionHandlerType {
    /// Low three bits stored in the clause flags field.
    pub const fn discriminant(self) -> u32 {
        match self {
            ExceptionHandlerType::Catch => 0,
            ExceptionHandlerType::Filter => 1,
            ExceptionHandlerType::Finally => 2,
            ExceptionHandlerType::Fault => 4,
        }
    }

    /// Decodes a handler kind from a clause flags value.
    pub const fn from_discriminant(raw: u32) -> Option<Self> {
        match raw & 0x7 {
            0 => Some(ExceptionHandlerType::Catch),
            1 => Some(ExceptionHandlerType::Filter),
            2 => Some(ExceptionHandlerType::Finally),
            4 => Some(ExceptionHandlerType::Fault),
            _ => None,
        }
    }
}

/// One structured exception-handling clause of a method body.
///
/// All offsets are absolute IL offsets; lengths are byte counts, matching
/// Cecil's `(start, end = start + length)` pairs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExceptionHandler {
    /// Offset of the first instruction inside the guarded try block.
    pub try_start: i32,
    /// Length in bytes of the try block.
    pub try_length: i32,
    /// Offset of the first handler instruction.
    pub handler_start: i32,
    /// Length in bytes of the handler block.
    pub handler_length: i32,
    /// Offset of the filter start for [`ExceptionHandlerType::Filter`].
    pub filter_start: Option<i32>,
    /// Caught exception type token for [`ExceptionHandlerType::Catch`].
    pub catch_type: Token,
    /// Handler kind.
    pub handler_type: ExceptionHandlerType,
}

impl ExceptionHandler {
    /// Creates a handler covering `[start, start + length)` ranges.
    pub fn new(handler_type: ExceptionHandlerType) -> Self {
        ExceptionHandler {
            try_start: 0,
            try_length: 0,
            handler_start: 0,
            handler_length: 0,
            filter_start: None,
            catch_type: Token::NIL,
            handler_type,
        }
    }
}

const EH_TABLE: u8 = 0x1;
const FAT_FORMAT: u8 = 0x40;
const MORE_SECTS: u8 = 0x80;

/// Size in bytes of one small-form clause.
pub const SMALL_CLAUSE_SIZE: usize = 12;
/// Size in bytes of one fat-form clause.
pub const FAT_CLAUSE_SIZE: usize = 24;

/// Writes a single clause in the given form.
///
/// `fat == false` selects the small form (12-byte entries); offsets must fit
/// their narrow fields or an error is returned.
pub fn write_clause(out: &mut ByteWriter, handler: &ExceptionHandler, fat: bool) -> Result<()> {
    let kind = handler.handler_type.discriminant();
    if fat {
        out.u32(kind);
        out.i32(handler.try_start);
        out.i32(handler.try_length);
        out.i32(handler.handler_start);
        out.i32(handler.handler_length);
        match handler.handler_type {
            ExceptionHandlerType::Catch => out.u32(handler.catch_type.0),
            ExceptionHandlerType::Filter => {
                out.i32(handler.filter_start.unwrap_or_default())
            }
            ExceptionHandlerType::Finally | ExceptionHandlerType::Fault => out.u32(0),
        }
    } else {
        if handler.try_start < 0 || handler.try_start > u16::MAX as i32 {
            return Err(Error::invalid_op("try offset does not fit a small clause"));
        }
        if handler.try_length < 0 || handler.try_length > u8::MAX as i32 {
            return Err(Error::invalid_op("try length does not fit a small clause"));
        }
        if handler.handler_start < 0 || handler.handler_start > u16::MAX as i32 {
            return Err(Error::invalid_op(
                "handler offset does not fit a small clause",
            ));
        }
        if handler.handler_length < 0 || handler.handler_length > u8::MAX as i32 {
            return Err(Error::invalid_op(
                "handler length does not fit a small clause",
            ));
        }
        if handler.handler_type == ExceptionHandlerType::Filter
            && handler
                .filter_start
                .map_or(false, |f| f < 0 || f > u16::MAX as i32)
        {
            return Err(Error::invalid_op(
                "filter offset does not fit a small clause",
            ));
        }
        out.u16(kind as u16);
        out.u16(handler.try_start as u16);
        out.u8(handler.try_length as u8);
        out.u16(handler.handler_start as u16);
        out.u8(handler.handler_length as u8);
        match handler.handler_type {
            ExceptionHandlerType::Catch => out.u32(handler.catch_type.0),
            ExceptionHandlerType::Filter => {
                out.u32(handler.filter_start.unwrap_or_default() as u32)
            }
            ExceptionHandlerType::Finally | ExceptionHandlerType::Fault => out.u32(0),
        }
    }
    Ok(())
}

/// Reads a single clause in the given form starting at the reader position.
pub fn read_clause(reader: &mut ByteReader<'_>, fat: bool) -> Result<ExceptionHandler> {
    let (kind_raw, try_start, try_len, handler_start, handler_len): (
        u32,
        i32,
        i32,
        i32,
        i32,
    ) = if fat {
        (
            reader.u32()?,
            reader.i32()?,
            reader.i32()?,
            reader.i32()?,
            reader.i32()?,
        )
    } else {
        (
            reader.u16()? as u32,
            reader.u16()? as i32,
            reader.u8()? as i32,
            reader.u16()? as i32,
            reader.u8()? as i32,
        )
    };

    let handler_type = ExceptionHandlerType::from_discriminant(kind_raw)
        .ok_or_else(|| Error::bad_image(format!("invalid exception clause kind {kind_raw:#x}")))?;

    let mut handler = ExceptionHandler::new(handler_type);
    handler.try_start = try_start;
    handler.try_length = try_len;
    handler.handler_start = handler_start;
    handler.handler_length = handler_len;

    match handler_type {
        ExceptionHandlerType::Catch => handler.catch_type = Token(reader.u32()?),
        ExceptionHandlerType::Filter => handler.filter_start = Some(reader.i32()?),
        ExceptionHandlerType::Finally | ExceptionHandlerType::Fault => {
            reader.read_bytes(4)?;
        }
    }
    Ok(handler)
}

/// Chooses between the small and the fat section form using Cecil's rules:
/// more than 0x14 handlers, any range beyond the small-field limits, or an
/// explicitly forced fat layout select the fat form.
pub fn requires_fat_section(handlers: &[ExceptionHandler], force_fat: bool) -> bool {
    if force_fat || handlers.len() >= 0x15 {
        return true;
    }
    handlers.iter().any(|h| {
        h.try_start > u16::MAX as i32
            || h.try_length > u8::MAX as i32
            || h.handler_start > u16::MAX as i32
            || h.handler_length > u8::MAX as i32
            || h.filter_start.is_some_and(|f| f > u16::MAX as i32)
    })
}

/// Encodes one exception-handling section (without leading alignment).
///
/// `force_fat` overrides the size heuristics; pass `false` to pick the most
/// compact legal form like Cecil's `CodeWriter.WriteExceptionHandlers`.
pub fn write_section(handlers: &[ExceptionHandler], force_fat: bool) -> Result<Vec<u8>> {
    let fat = requires_fat_section(handlers, force_fat);
    let mut w = ByteWriter::new();
    if fat {
        let size = handlers.len() * FAT_CLAUSE_SIZE + 4;
        if size > 0xFF_FFFF {
            return Err(Error::invalid_op("exception section too large"));
        }
        w.u8(EH_TABLE | FAT_FORMAT);
        // Three little-endian bytes of the 24-based data size.
        w.u8((size & 0xFF) as u8);
        w.u8(((size >> 8) & 0xFF) as u8);
        w.u8(((size >> 16) & 0xFF) as u8);
    } else {
        let size = handlers.len() * SMALL_CLAUSE_SIZE + 4;
        if size > 0xFF {
            return Err(Error::invalid_op("exception section too large"));
        }
        w.u8(EH_TABLE);
        w.u8(size as u8);
        w.u16(0); // padding to 4-byte alignment
    }
    for handler in handlers {
        write_clause(&mut w, handler, fat)?;
    }
    Ok(w.into_vec())
}

/// Parses the exception-handling sections that follow a method body's code.
///
/// `data` starts at the (already 4-aligned) first section; chained sections
/// (`more_sects`) are followed automatically. Returns the collected handlers
/// and whether another section had been flagged.
pub fn parse_sections(data: &[u8]) -> Result<(Vec<ExceptionHandler>, bool)> {
    let mut handlers = Vec::new();
    let mut reader = ByteReader::new(data);
    loop {
        let flags = reader.u8()?;
        if flags & EH_TABLE == 0 {
            return Err(Error::bad_image("section without eh_table flag"));
        }
        let fat = flags & FAT_FORMAT != 0;
        let count = if fat {
            let b0 = reader.u8()?;
            let b1 = reader.u8()?;
            let b2 = reader.u8()?;
            let size = b0 as usize | (b1 as usize) << 8 | (b2 as usize) << 16;
            size / FAT_CLAUSE_SIZE
        } else {
            let size = reader.u8()? as usize;
            reader.read_bytes(2)?;
            size / SMALL_CLAUSE_SIZE
        };
        for _ in 0..count {
            handlers.push(read_clause(&mut reader, fat)?);
        }
        if flags & MORE_SECTS == 0 {
            return Ok((handlers, false));
        }
        // Chained sections repeat at the next 4-byte boundary relative to
        // the section stream start.
        reader.align(4)?;
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn sample_handlers() -> Vec<ExceptionHandler> {
        let mut catch = ExceptionHandler::new(ExceptionHandlerType::Catch);
        catch.try_start = 4;
        catch.try_length = 20;
        catch.handler_start = 24;
        catch.handler_length = 12;
        catch.catch_type = Token(0x0100_0015);
        assert_eq!(SMALL_CLAUSE_SIZE, 12);
        assert_eq!(FAT_CLAUSE_SIZE, 24);

        let mut filter = ExceptionHandler::new(ExceptionHandlerType::Filter);
        filter.try_start = 40;
        filter.try_length = 30;
        filter.handler_start = 80;
        filter.handler_length = 16;
        filter.filter_start = Some(70);

        let mut finally = ExceptionHandler::new(ExceptionHandlerType::Finally);
        finally.try_start = 100;
        finally.try_length = 50;
        finally.handler_start = 150;
        finally.handler_length = 20;

        let mut fault = ExceptionHandler::new(ExceptionHandlerType::Fault);
        fault.try_start = 200;
        fault.try_length = 10;
        fault.handler_start = 210;
        fault.handler_length = 8;

        vec![catch, filter, finally, fault]
    }

    /// Acceptance #3: small-form roundtrip preserves offsets, lengths, kind.
    #[test]
    fn small_section_roundtrip() {
        let handlers = sample_handlers();
        let bytes = write_section(&handlers, false).unwrap();
        // 4 handlers * 12 + 4 header bytes.
        assert_eq!(bytes.len(), 4 * SMALL_CLAUSE_SIZE + 4);
        let (parsed, more) = parse_sections(&bytes).unwrap();
        assert!(!more);
        assert_eq!(parsed, handlers);
    }

    /// Acceptance #3: fat-form roundtrip preserves offsets, lengths, kind.
    #[test]
    fn fat_section_roundtrip() {
        let mut handlers = sample_handlers();
        for h in &mut handlers {
            h.try_start += 100_000; // beyond small-form limits
            h.try_length *= 100; // beyond one byte
        }
        let bytes = write_section(&handlers, false).unwrap();
        assert_eq!(bytes.len(), 4 * FAT_CLAUSE_SIZE + 4);
        let (parsed, _) = parse_sections(&bytes).unwrap();
        assert_eq!(parsed, handlers);

        // Forced-fat encoding of small-range values stays equivalent.
        let small = sample_handlers();
        let forced = write_section(&small, true).unwrap();
        let (parsed_forced, _) = parse_sections(&forced).unwrap();
        assert_eq!(parsed_forced, small);
    }

    /// Small <-> fat conversion preserves the semantic content.
    #[test]
    fn small_to_fat_conversion_preserves_semantics() {
        let handlers = sample_handlers();
        let small_bytes = write_section(&handlers, false).unwrap();
        let (from_small, _) = parse_sections(&small_bytes).unwrap();

        let fat_bytes = write_section(&handlers, true).unwrap();
        let (from_fat, _) = parse_sections(&fat_bytes).unwrap();

        assert_eq!(from_small, from_fat);
        assert_eq!(from_fat.len(), handlers.len());
        for (a, b) in from_fat.iter().zip(handlers.iter()) {
            assert_eq!(
                (a.try_start, a.try_length, a.handler_start, a.handler_length),
                (b.try_start, b.try_length, b.handler_start, b.handler_length)
            );
            assert_eq!(a.handler_type, b.handler_type);
        }
    }

    #[test]
    fn small_rejects_out_of_range_values() {
        let mut handler = ExceptionHandler::new(ExceptionHandlerType::Finally);
        handler.try_start = 70_000;
        assert!(write_clause(&mut ByteWriter::new(), &handler, false).is_err());

        handler.try_start = 1;
        handler.handler_length = 300;
        assert!(write_clause(&mut ByteWriter::new(), &handler, false).is_err());
    }

    #[test]
    fn requires_fat_heuristics_match_cecil() {
        let handlers = sample_handlers();
        assert!(!requires_fat_section(&handlers, false));
        assert!(requires_fat_section(&handlers, true));

        let mut many: Vec<ExceptionHandler> = Vec::new();
        for i in 0..0x15u32 {
            let mut h = ExceptionHandler::new(ExceptionHandlerType::Finally);
            h.try_start = i as i32;
            many.push(h);
        }
        // 21 handlers still fit the size byte (21*12+4 = 256 > 255 actually
        // forces fat through write_section, but the heuristic itself is
        // count >= 0x15).
        assert!(requires_fat_section(&many, false));
    }
}
