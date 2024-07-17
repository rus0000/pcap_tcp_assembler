/*
 * @copyright (C) smoltcp authors <https://github.com/smoltcp-rs/smoltcp>
 * @copyright (C) 2024 Ruslan Iusupov <https://github.com/rus0000>
 *
 * SPDX-License-Identifier: 0BSD
 */
use core::fmt;
use std::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssemblerError {
    RuntimeError,
    TooManyHolesError,
}
impl fmt::Display for AssemblerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AssemblerError::RuntimeError => write!(f, "runtime error"),
            AssemblerError::TooManyHolesError => write!(f, "too many holes error"),
        }
    }
}

impl Error for AssemblerError {}

/// A contiguous chunk of absent data, followed by a contiguous chunk of present data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Contig {
    hole_size: usize,
    data_size: usize,
}

impl fmt::Display for Contig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.has_hole() {
            write!(f, "({})", self.hole_size)?;
        }
        if self.has_hole() && self.has_data() {
            write!(f, " ")?;
        }
        if self.has_data() {
            write!(f, "{}", self.data_size)?;
        }
        Ok(())
    }
}

impl Contig {
    fn empty() -> Contig {
        Contig {
            hole_size: 0,
            data_size: 0,
        }
    }

    fn hole_and_data(hole_size: usize, data_size: usize) -> Contig {
        Contig {
            hole_size,
            data_size,
        }
    }

    fn has_hole(&self) -> bool {
        self.hole_size != 0
    }

    fn has_data(&self) -> bool {
        self.data_size != 0
    }

    fn get_total_size(&self) -> usize {
        self.hole_size + self.data_size
    }

    /// Decrease hole_size, do not adjust data_size
    fn decrease_hole_by(&mut self, size: usize) {
        self.hole_size -= size;
    }

    /// Decrease data_size, do not adjust hole_size
    // fn decrease_data_by(&mut self, size: usize) {
    //     self.data_size -= size;
    // }

    /// Set hole_size, increase data_size
    /// * `size` - new hole_size, must be less or equal to the current hole_size
    fn shrink_hole_to(&mut self, size: usize) -> usize{
        assert!(self.hole_size >= size);
        let difference = self.hole_size - size;

        if difference == 0 {
            return 0;
        }

        self.data_size += difference;
        self.hole_size = size;

        difference
    }
}

/// A buffer (re)assembler.
///
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Assembler {
    pub contigs: Vec::<Contig>,
}

impl fmt::Display for Assembler {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[ ")?;
        for contig in self.contigs.iter() {
            if !contig.has_data() {
                break;
            }
            write!(f, "{contig} ")?;
        }
        write!(f, "]")?;
        Ok(())
    }
}

// Invariant on Assembler::contigs:
// - There's an index `i` where all contigs before have data, and all contigs after don't (are unused).
// - All contigs with data must have hole_size != 0, except the first.

impl Assembler {
    /// Create a new buffer assembler.
    pub fn new(assembler_max_lost_segment_count: usize) -> Assembler {
        Assembler {
            contigs: vec![Contig::empty(); assembler_max_lost_segment_count]
        }
    }

    pub fn clear(&mut self) {
        self.contigs.fill(Contig::empty());
    }

    pub fn front(&self) -> Contig {
        self.contigs[0]
    }

    pub fn len(&self) -> usize {
        let mut total_len: usize = 0;
        for contig in self.contigs.iter() {
            if !contig.has_data() {
                break;
            }
            total_len += contig.get_total_size();
        }

        total_len
    }

    /// Return length of the front contiguous range without removing it from the assembler
    pub fn peek_front(&self) -> usize {
        let front = self.front();
        if front.has_hole() {
            0
        } else {
            front.data_size
        }
    }

    pub fn back(&self) -> Contig {
        self.contigs[self.contigs.len() - 1]
    }

    /// Return whether the assembler contains no data.
    pub fn is_empty(&self) -> bool {
        !self.front().has_data()
    }

    /// Remove a contig at the given index.
    /// Do not modify hole and data in any of contigs.
    pub fn remove_contig_at_index(&mut self, index: usize) {
        debug_assert!(self.contigs[index].has_data());

        for i in index..(self.contigs.len() - 1) {
            if !self.contigs[i].has_data() {
                return;
            }
            self.contigs[i] = self.contigs[i + 1];
        }

        // Removing the last one.
        let len = self.contigs.len();
        self.contigs[len - 1] = Contig::empty();
    }

    /// Insert a contig at the given index, and return mut pointer to it.
    /// Do not modify hole and data in any of contigs.
    pub fn insert_contig_at_index(&mut self, index: usize) -> Result<&mut Contig, AssemblerError> {
        if self.back().has_data() {
            return Err(AssemblerError::TooManyHolesError);
        }

        for i in ((index + 1)..self.contigs.len()).rev() {
            self.contigs[i] = self.contigs[i - 1];
        }

        self.contigs[index] = Contig::empty();

        Ok(&mut self.contigs[index])
    }

    /// Remove a contiguous range from the front of the assembler.
    /// Return removed range data_size.
    /// If no such range, return 0.
    pub fn remove_contiguous_data_from_head(&mut self) -> usize {
        let front = self.front();
        if front.has_hole() || !front.has_data() {
            0
        } else {
            let front_data_size = front.data_size;
            debug_assert!(front_data_size > 0);

            self.remove_contig_at_index(0);

            front_data_size
        }
    }

    /// Insert a new segment of data into the assembler, then remove_contiguous_data_from_head.
    ///
    /// This is equivalent to calling `insert_data` then `remove_contiguous_data_from_head` individually,
    /// except it's guaranteed to not fail when offset = 0.
    /// This is required for TCP: we must never drop the next expected segment, or
    /// the protocol might get stuck.
    pub fn insert_then_remove_contiguous_data_from_head(
        &mut self,
        offset: usize,
        size: usize,
    ) -> Result<usize, AssemblerError> {
        // This is the only case where a segment at offset=0 would cause the
        // total amount of contigs to rise (and therefore can potentially cause
        // a AssemblerError::TooManyHolesError). Handle it in a way that is guaranteed to succeed.
        if offset == 0 && size < self.contigs[0].hole_size {
            self.contigs[0].hole_size -= size;
            return Ok(size);
        }

        self.insert_data_absolute(offset, size)?;
        Ok(self.remove_contiguous_data_from_head())
    }

    /// Find contig_index and relative desired offset inside of it for given offset.
    /// # Arguments
    /// `offset` - offset from beginning of assembler, zero-based
    /// # Return
    /// - `(contig_index, offset_in_contig)`
    ///     - `contig_index` - Starts from 0.
    ///     - `offset_in_contig` - Relative offset inside found contig, starts from 0.
    ///         - Not taking into account existing contig's hole_size or data_size, this is just a relative reminder inside found contig
    /// # Example
    /// - Given assembler state (10, 10), (10, 10) and argument offset: 20
    /// - Will return (contig_index: 1, offset_in_contig: 0)
    pub fn find_contig_by_offset(&self, offset: usize) -> Result<(usize, usize), AssemblerError> {
        let mut contig_index = 0;
        let mut offset_in_contig = offset;

        // Find index of the contig containing the start of the range.
        // Also find a relative offset of data in found contig.
        loop {
            if contig_index == self.contigs.len() {
                // The range is after all the previous ranges.
                return Err(AssemblerError::RuntimeError);
            }
            let contig = &self.contigs[contig_index];
            if !contig.has_data() {
                // The new range is after all the previous ranges.
                return Ok((contig_index, offset_in_contig));
            }
            if offset_in_contig < contig.get_total_size() {
                break;
            }
            offset_in_contig -= contig.get_total_size();
            contig_index += 1;
        }

        // data_offset_in_contig now points at the start of data inside found contig with contig_index

        Ok((contig_index, offset_in_contig))
    }

    /// Insert a new segment of data into the assembler, adjust holes.
    /// Return modified contig number
    /// Return `Err(AssemblerError::TooManyHolesError)` if too many discontinuities are already recorded.
    /// * `data_offset` - position of data from beginning of Assembler.
    ///     - This is relative and "floating" position. In the meaning, that it depends on the state of Assembler, which is dynamic.
    ///     - Assembler state is modified with remove_front and  methods, after that, notion of data_offset for every contig would be different.
    /// * `data_size` - data size to insert
    pub fn insert_data_absolute(&mut self, data_offset: usize, data_size: usize) -> Result<usize, AssemblerError> {
        if data_size == 0 {
            return Ok(0);
        }

        let mut contig_index = 0;
        let mut data_offset_in_contig = data_offset;

        // Find index of the contig containing the start of the range.
        loop {
            if contig_index == self.contigs.len() {
                // The new range is after all the previous ranges, but there/s no space to add it.
                return Err(AssemblerError::TooManyHolesError);
            }
            let contig = &mut self.contigs[contig_index];
            if !contig.has_data() {
                // The new range is after all the previous ranges. Add it.
                *contig = Contig::hole_and_data(data_offset_in_contig, data_size);
                return Ok(contig_index);
            }
            if data_offset_in_contig <= contig.get_total_size() {
                break;
            }
            data_offset_in_contig -= contig.get_total_size();
            contig_index += 1;
        }
        // data_offset_in_contig now points at the desired start of data inside found contig with contig_index

        let contig = &mut self.contigs[contig_index];
        if data_offset_in_contig < contig.hole_size {
            // Range starts within the hole.

            if data_offset_in_contig + data_size < contig.hole_size {
                // Range also ends within the hole.
                let new_contig = self.insert_contig_at_index(contig_index)?;
                new_contig.hole_size = data_offset_in_contig;
                new_contig.data_size = data_size;

                // Previous contigs[index] got moved to contigs[index+1]
                self.contigs[contig_index + 1].decrease_hole_by(data_offset_in_contig + data_size);

                return Ok(contig_index);
            }

            // The range being added covers both a part of the hole and a part of the data
            // in this contig, shrink the hole in this contig. This will increase data_size.
            contig.shrink_hole_to(data_offset_in_contig);
        }

        // Merge all covered contigs to the right into the current contig.
        let mut j = contig_index + 1;
        while j < self.contigs.len()
            && self.contigs[j].has_data()
            && data_offset_in_contig + data_size >= self.contigs[contig_index].get_total_size() + self.contigs[j].hole_size
        {
            self.contigs[contig_index].data_size += self.contigs[j].get_total_size();
            j += 1;
        }

        // Shift all other contigs after merged contigs to the left.
        let shift = j - contig_index - 1;
        if shift != 0 {
            for x in (contig_index + 1)..self.contigs.len() {
                if !self.contigs[x].has_data() {
                    break;
                }

                self.contigs[x] = self
                    .contigs
                    .get(x + shift)
                    .copied()
                    // x + shift went beyond self.contigs.len(), just put empty contig
                    .unwrap_or_else(Contig::empty);
            }
        }

        // TODO: Case is not clear. Check if covered by test.
        if data_offset_in_contig + data_size > self.contigs[contig_index].get_total_size() {
            // The added range still extends beyond the current contig. Increase data size.
            let left = data_offset_in_contig + data_size - self.contigs[contig_index].get_total_size();
            self.contigs[contig_index].data_size += left;

            // Decrease hole size of the next, if any.
            if contig_index + 1 < self.contigs.len() && self.contigs[contig_index + 1].has_data() {
                self.contigs[contig_index + 1].hole_size -= left;
            }
        }

        Ok(contig_index)
    }

    pub fn is_last_contig(&self, contig_index: usize) -> bool {
        contig_index == self.contigs.len()
    }

    /// Remove data from Assembler, adjust contigs.
    /// Range must start and end within one contig
    /// Same as inserting a hole.
    /// # Arguments
    /// * `offset` - position of data from beginning of Assembler, where to remove data.
    ///     - This is relative and "floating" position. In the meaning, that it depends on the state of Assembler head, which is dynamic.
    ///     - Assembler head state is modified with `remove_front()` and `remove_data_at_head()` methods. After that, notion of offset for all contigs would be different.
    /// * `remove_data_size` - data size to remove
    pub fn remove_data(&mut self, offset: usize, remove_data_size: usize) -> Result<(), AssemblerError> {
        if remove_data_size == 0 {
            return Ok(());
        }

        // data_offset_in_contig points at the desired start of data inside found contig with returned contig_index.
        let (contig_index, data_offset_in_contig) = self.find_contig_by_offset(offset)?;

        let contig = &mut self.contigs[contig_index];
        if !contig.has_data() {
            return Ok(());
        }

        // Mainstream case. Contig is fully covered. Remove this contig, Adjust next contig hole.
        if remove_data_size >= contig.data_size && data_offset_in_contig + remove_data_size == contig.get_total_size() {
            if !self.is_last_contig(contig_index) && self.contigs[contig_index + 1].has_hole() {
                self.contigs[contig_index + 1].hole_size += self.contigs[contig_index].get_total_size();
            }
            self.remove_contig_at_index(contig_index);

            return Ok(());
        }

        let old_data_size = contig.data_size;
        // let old_hole_size = contig.hole_size;
        let old_total_size = contig.get_total_size();

        // Range starts and ends within contig.
        if data_offset_in_contig + remove_data_size <= old_total_size {
            // Range starts and ends within the contig hole.
            if data_offset_in_contig + remove_data_size <= contig.hole_size {
                return Ok(());
            }
            // Range starts within the contig hole and ends within contig data.
            // TODO: Implementing span of hole over multiple contigs will make this case not needed
            if data_offset_in_contig < contig.hole_size {
                let hole_increase = data_offset_in_contig + remove_data_size - contig.hole_size;
                contig.hole_size += hole_increase;
                assert!(contig.data_size > hole_increase);
                contig.data_size -= hole_increase;

                // If empty, add hole to the next contig and shift contigs.
                // if contig.data_size == 0 && !self.is_last_contig(contig_index ) && self.contigs[contig_index + 1].has_data() {
                //     self.contigs[contig_index + 1].hole_size += old_total_size;
                //     self.remove_contig_at_index(contig_index);
                // }

                return Ok(());
            }
            // Range starts and ends within contig data and not all of data needs to be removed because it is checked before (Mainstream).
            debug_assert!(data_offset_in_contig >= contig.hole_size);
            let left_data_size = data_offset_in_contig - contig.hole_size;

            if left_data_size == 0 {
                contig.hole_size += remove_data_size;
                contig.data_size -= remove_data_size;

                return Ok(());
            }

            contig.data_size = left_data_size;
            let right_data_size = old_total_size - (data_offset_in_contig + remove_data_size);
            // Increase hole at next contig
            // println!("{left_data_size} {right_data_size}");
            if right_data_size == 0 {
                if !self.is_last_contig(contig_index) && self.contigs[contig_index + 1].has_data() {
                    self.contigs[contig_index + 1].hole_size += old_data_size - left_data_size;
                }

                return Ok(());
            } else  {
                // Cannot store more data.
                if self.is_last_contig(contig_index) {
                    return Err(AssemblerError::RuntimeError);
                }
                let new_contig = self.insert_contig_at_index(contig_index +1)?;
                new_contig.hole_size = remove_data_size;
                new_contig.data_size = right_data_size;

                return Ok(());
            }
        }

        Err(AssemblerError::RuntimeError)
    }

    /// Truncate Assembler at head
    /// Account hole_size and data_size
    pub fn remove_data_at_head(
        &mut self,
        remove_data_size: usize,
    ) -> Result<(), AssemblerError> {
        if remove_data_size == 0 {
            return Ok(());
        }
        if !self.contigs[0].has_data() {
            return Ok(());
        }
        let offset = remove_data_size - 1;
        let (contig_index, data_offset_in_contig) = self.find_contig_by_offset(offset)?;
        if !self.contigs[contig_index].has_data() {
            return Ok(());
        }
        if contig_index > 0 {
            for i in 0..contig_index {
                self.remove_contig_at_index(i);
            }
        }

        if self.remove_data(0, data_offset_in_contig + 1).is_err() {
            return Err(AssemblerError::RuntimeError);
        }
        self.decrease_leading_hole(data_offset_in_contig + 1)
    }
    pub fn decrease_leading_hole(
        &mut self,
        bytes_to_remove_from_hole: usize,
    ) -> Result<(), AssemblerError> {
        if bytes_to_remove_from_hole == 0 {
            return Ok(());
        }
        if !self.contigs[0].has_data() {
            return Ok(());
        }
        if self.contigs[0].hole_size < bytes_to_remove_from_hole {
            return Err(AssemblerError::RuntimeError);
        }
        self.contigs[0].decrease_hole_by(bytes_to_remove_from_hole);

        return Ok(());
    }

    pub fn get_contig_hole_and_data(
        &self,
        contig_id: usize,
    ) -> (usize, usize) {
        (self.contigs[contig_id].hole_size, self.contigs[contig_id].data_size)
    }

    /// Return contig data offset and data_size
    pub fn get_contig_data(
        &self,
        contig_id: usize,
    ) -> (usize, usize) {
        let mut offset = 0;
        let mut size = 0;
        for i in 0..self.contigs.len() - 1 {
            if i == contig_id {
                offset += self.contigs[i].hole_size;
                size = self.contigs[i].data_size;

                return (offset, size)
            } else {
                offset += self.contigs[i].get_total_size();
            }
        }

        (offset, size)
    }

    /// Iterate over all of the contiguous data ranges.
    ///
    /// This is used in calculating what data ranges have been received. The offset indicates the
    /// number of bytes of contiguous data received before the beginnings of this Assembler.
    ///
    ///    Data        Hole        Data
    /// |--- 100 ---|--- 200 ---|--- 100 ---|
    ///
    /// An offset of 1500 would return the ranges: ``(1500, 1600), (1800, 1900)``
    pub fn iter_data(&self, first_offset: usize) -> AssemblerIter {
        AssemblerIter::new(self, first_offset)
    }
}

pub struct AssemblerIter<'a> {
    assembler: &'a Assembler,
    offset: usize,
    contig_index: usize,
    left: usize,
    right: usize,
}

impl<'a> AssemblerIter<'a> {
    fn new(assembler: &'a Assembler, offset: usize) -> AssemblerIter<'a> {
        AssemblerIter {
            assembler,
            offset,
            contig_index: 0,
            left: 0,
            right: 0,
        }
    }
}

impl<'a> Iterator for AssemblerIter<'a> {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<(usize, usize)> {
        let mut data_range = None;
        while data_range.is_none() && self.contig_index < self.assembler.contigs.len() {
            let contig = self.assembler.contigs[self.contig_index];
            self.left += contig.hole_size;
            self.right = self.left + contig.data_size;
            data_range = if self.left < self.right {
                let data_range = (self.left + self.offset, self.right + self.offset);
                self.left = self.right;
                Some(data_range)
            } else {
                None
            };
            self.contig_index += 1;
        }
        data_range
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::vec::Vec;
    const ASSEMBLER_MAX_LOST_SEGMENT_COUNT: usize = 10;

    impl From<Vec<(usize, usize)>> for Assembler {
        fn from(vec: Vec<(usize, usize)>) -> Assembler {
            let empty_contig: Contig = Contig::empty();

            let mut contigs = vec![empty_contig; ASSEMBLER_MAX_LOST_SEGMENT_COUNT];
            for (i, &(hole_size, data_size)) in vec.iter().enumerate() {
                contigs[i] = Contig {
                    hole_size,
                    data_size,
                };
            }
            Assembler { contigs }
        }
    }

    macro_rules! contigs {
        [$( $x:expr ),*] => ({
            Assembler::from(vec![$( $x ),*])
        })
    }

    #[test]
    fn test_is_last_contig_positive() {
        let assembler = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assembler.is_last_contig(ASSEMBLER_MAX_LOST_SEGMENT_COUNT), true);
    }

    #[test]
    fn test_is_last_contig_negative() {
        let assembler = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assembler.is_last_contig(0), false);
        assert_eq!(assembler.is_last_contig(1), false);
        assert_eq!(assembler.is_last_contig(ASSEMBLER_MAX_LOST_SEGMENT_COUNT - 1), false);
    }

    #[test]
    fn test_find_contig_by_offset_empty() {
        let assembler = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assembler.find_contig_by_offset(0), Ok((0, 0)));
        assert_eq!(assembler.find_contig_by_offset(1), Ok((0, 1)));
        assert_eq!(assembler.find_contig_by_offset(2), Ok((0, 2)));
    }

    #[test]
    fn test_find_contig_by_offset_positive1() {
        let mut assembler = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assembler.insert_data_absolute(0, 10), Ok(0));
        assert_eq!(assembler.find_contig_by_offset(0), Ok((0, 0)));
        assert_eq!(assembler.find_contig_by_offset(1), Ok((0, 1)));
        assert_eq!(assembler.find_contig_by_offset(5), Ok((0, 5)));
        assert_eq!(assembler.find_contig_by_offset(9), Ok((0, 9)));
        assert_eq!(assembler.find_contig_by_offset(10), Ok((1, 0)));
        assert_eq!(assembler.find_contig_by_offset(11), Ok((1, 1)));
        assert_eq!(assembler.find_contig_by_offset(12), Ok((1, 2)));
    }

    #[test]
    fn test_find_contig_by_offset_positive2() {
        let mut assembler = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assembler.insert_data_absolute(10, 10), Ok(0));
        assert_eq!(assembler.insert_data_absolute(30, 10), Ok(1));
        assert_eq!(assembler.insert_data_absolute(50, 10), Ok(2));
        assert_eq!(assembler, contigs![(10, 10), (10, 10), (10, 10)]);
        assert_eq!(assembler.find_contig_by_offset(0), Ok((0, 0)));
        assert_eq!(assembler.find_contig_by_offset(1), Ok((0, 1)));
        assert_eq!(assembler.find_contig_by_offset(5), Ok((0, 5)));
        assert_eq!(assembler.find_contig_by_offset(9), Ok((0, 9)));
        assert_eq!(assembler.find_contig_by_offset(10), Ok((0, 10)));
        assert_eq!(assembler.find_contig_by_offset(11), Ok((0, 11)));
        assert_eq!(assembler.find_contig_by_offset(12), Ok((0, 12)));
        assert_eq!(assembler.find_contig_by_offset(19), Ok((0, 19)));
        assert_eq!(assembler.find_contig_by_offset(20), Ok((1, 0)));
        assert_eq!(assembler.find_contig_by_offset(21), Ok((1, 1)));
        assert_eq!(assembler.find_contig_by_offset(22), Ok((1, 2)));
        assert_eq!(assembler.find_contig_by_offset(29), Ok((1, 9)));
        assert_eq!(assembler.find_contig_by_offset(30), Ok((1, 10)));
        assert_eq!(assembler.find_contig_by_offset(31), Ok((1, 11)));
        assert_eq!(assembler.find_contig_by_offset(39), Ok((1, 19)));
        assert_eq!(assembler.find_contig_by_offset(40), Ok((2, 0)));
        assert_eq!(assembler.find_contig_by_offset(41), Ok((2, 1)));
        assert_eq!(assembler.find_contig_by_offset(59), Ok((2, 19)));
        assert_eq!(assembler.find_contig_by_offset(60), Ok((3, 0)));
        assert_eq!(assembler.find_contig_by_offset(61), Ok((3, 1)));
    }

    #[test]
    fn test_find_contig_by_offset_positive3() {
        let mut assembler = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assembler.insert_data_absolute(0, 10), Ok(0));
        assert_eq!(assembler.insert_data_absolute(20, 10), Ok(1));
        assert_eq!(assembler.insert_data_absolute(40, 10), Ok(2));
        assert_eq!(assembler, contigs![(0, 10), (10, 10), (10, 10)]);
        assert_eq!(assembler.find_contig_by_offset(0), Ok((0, 0)));
        assert_eq!(assembler.find_contig_by_offset(1), Ok((0, 1)));
        assert_eq!(assembler.find_contig_by_offset(5), Ok((0, 5)));
        assert_eq!(assembler.find_contig_by_offset(9), Ok((0, 9)));
        assert_eq!(assembler.find_contig_by_offset(10), Ok((1, 0)));
        assert_eq!(assembler.find_contig_by_offset(11), Ok((1, 1)));
        assert_eq!(assembler.find_contig_by_offset(12), Ok((1, 2)));
        assert_eq!(assembler.find_contig_by_offset(19), Ok((1, 9)));
        assert_eq!(assembler.find_contig_by_offset(20), Ok((1, 10)));
        assert_eq!(assembler.find_contig_by_offset(21), Ok((1, 11)));
        assert_eq!(assembler.find_contig_by_offset(22), Ok((1, 12)));
        assert_eq!(assembler.find_contig_by_offset(29), Ok((1, 19)));
        assert_eq!(assembler.find_contig_by_offset(30), Ok((2, 0)));
        assert_eq!(assembler.find_contig_by_offset(31), Ok((2, 1)));
    }

    #[test]
    fn test_fmt() {
        let mut assembler = Assembler::new(5);
        assert_eq!(assembler.insert_data_absolute(10, 10), Ok(0));
        assert_eq!(assembler.insert_data_absolute(30, 10), Ok(1));
        assert_eq!(assembler.insert_data_absolute(50, 10), Ok(2));
        assert_eq!(format!("{}", assembler), "[ (10) 10 (10) 10 (10) 10 ]");
        assert_eq!(format!("{:?}", assembler), "Assembler { contigs: [Contig { hole_size: 10, data_size: 10 }, Contig { hole_size: 10, data_size: 10 }, Contig { hole_size: 10, data_size: 10 }, Contig { hole_size: 0, data_size: 0 }, Contig { hole_size: 0, data_size: 0 }] }");
    }

    #[test]
    fn test_remove_data_empty() {
        let mut assembler = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 0
        assert_eq!(assembler.remove_data(0, 1), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 00
        assert_eq!(assembler.remove_data(0, 2), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000
        assert_eq!(assembler.remove_data(0, 3), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // -0
        assert_eq!(assembler.remove_data(1, 0), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // --0
        assert_eq!(assembler.remove_data(2, 0), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // ---0
        assert_eq!(assembler.remove_data(3, 0), Ok(()));
    }

    #[test]
    fn test_remove_data_within_hole1() {
        let mut assembler = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 00000000001111111111
        assert_eq!(assembler.insert_data_absolute(10, 10), Ok(0));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 0
        assert_eq!(assembler.remove_data(0, 1), Ok(()));
        assert_eq!(assembler, contigs![(10, 10)]);
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 00
        assert_eq!(assembler.remove_data(0, 2), Ok(()));
        assert_eq!(assembler, contigs![(10, 10)]);
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000
        assert_eq!(assembler.remove_data(0, 3), Ok(()));
        assert_eq!(assembler, contigs![(10, 10)]);
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // ?0
        assert_eq!(assembler.remove_data(1, 1), Ok(()));
        assert_eq!(assembler, contigs![(10, 10)]);
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // ??0
        assert_eq!(assembler.remove_data(2, 1), Ok(()));
        assert_eq!(assembler, contigs![(10, 10)]);
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // ?????????0
        assert_eq!(assembler.remove_data(9, 1), Ok(()));
        assert_eq!(assembler, contigs![(10, 10)]);
    }
    #[test]
    fn test_remove_data_within_hole2() {
        let mut assembler = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assembler.insert_data_absolute(10, 10), Ok(0));
        assert_eq!(assembler.insert_data_absolute(30, 10), Ok(1));
        assert_eq!(assembler.insert_data_absolute(50, 10), Ok(2));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000000000011111111110000000000111111111100000000001111111111
        assert_eq!(assembler, contigs![(10, 10), (10, 10), (10, 10)]);
        // Range covers full contig hole.
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // --------------------0000000000
        assert_eq!(assembler.remove_data(20, 10), Ok(()));
        assert_eq!(assembler, contigs![(10, 10), (10, 10), (10, 10)]);
    }

    #[test]
    fn test_remove_data_full1() {
        let mut assembler = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 1111111111
        assert_eq!(assembler.insert_data_absolute(0, 10), Ok(0));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 0000000000
        assert_eq!(assembler.remove_data(0, 10), Ok(()));
        assert_eq!(assembler, contigs![]);
    }
    #[test]
    fn test_remove_data_full2() {
        let mut assembler = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 00000000001111111111
        assert_eq!(assembler.insert_data_absolute(10, 10), Ok(0));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // ----------0000000000
        assert_eq!(assembler.remove_data(10, 10), Ok(()));
        assert_eq!(assembler, contigs![]);
    }
    #[test]
    fn test_remove_data_full3() {
        let mut assembler = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assembler.insert_data_absolute(10, 10), Ok(0));
        assert_eq!(assembler.insert_data_absolute(30, 10), Ok(1));
        assert_eq!(assembler.insert_data_absolute(50, 10), Ok(2));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000000000011111111110000000000111111111100000000001111111111
        assert_eq!(assembler, contigs![(10, 10), (10, 10), (10, 10)]);
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // ----------0000000000
        assert_eq!(assembler.remove_data(10, 10), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000000000000000000000000000000111111111100000000001111111111
        assert_eq!(assembler, contigs![(30, 10), (10, 10)]);
    }
    #[test]
    fn test_remove_data_full4() {
        let mut assembler = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assembler.insert_data_absolute(10, 10), Ok(0));
        assert_eq!(assembler.insert_data_absolute(30, 10), Ok(1));
        assert_eq!(assembler.insert_data_absolute(50, 10), Ok(2));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000000000011111111110000000000111111111100000000001111111111
        assert_eq!(assembler, contigs![(10, 10), (10, 10), (10, 10)]);
        // ------------------------------0000000000
        assert_eq!(assembler.remove_data(30, 10), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000000000011111111110000000000000000000000000000001111111111
        assert_eq!(assembler, contigs![(10, 10), (30, 10)]);
    }
    #[test]
    fn test_remove_data_full5() {
        let mut assembler = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assembler.insert_data_absolute(10, 10), Ok(0));
        assert_eq!(assembler.insert_data_absolute(30, 10), Ok(1));
        assert_eq!(assembler.insert_data_absolute(50, 10), Ok(2));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000000000011111111110000000000111111111100000000001111111111
        assert_eq!(assembler, contigs![(10, 10), (10, 10), (10, 10)]);
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000000000011111111110000000000111111111100000000001111111111
        // --------------------------------------------------0000000000
        assert_eq!(assembler.remove_data(50, 10), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 0000000000111111111100000000001111111111
        assert_eq!(assembler, contigs![(10, 10), (10, 10)]);
    }
    #[test]
    fn test_remove_data_full6() {
        let mut assembler = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assembler.insert_data_absolute(10, 10), Ok(0));
        assert_eq!(assembler.insert_data_absolute(30, 15), Ok(1));
        assert_eq!(assembler.insert_data_absolute(55, 20), Ok(2));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000000000011111111110000000000111111111111111000000000011111111111111111111
        assert_eq!(assembler, contigs![(10, 10), (10, 15), (10, 20)]);
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // --------------------0000000000000000000000000
        assert_eq!(assembler.remove_data(20, 25), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000000000011111111110000000000000000000000000000000000011111111111111111111
        assert_eq!(assembler, contigs![(10, 10), (35, 20)]);
    }
    #[test]
    fn test_remove_data_full7() {
        let mut assembler = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assembler.insert_data_absolute(10, 10), Ok(0));
        assert_eq!(assembler.insert_data_absolute(30, 15), Ok(1));
        assert_eq!(assembler.insert_data_absolute(55, 20), Ok(2));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000000000011111111110000000000111111111111111000000000011111111111111111111
        assert_eq!(assembler, contigs![(10, 10), (10, 15), (10, 20)]);
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // ------------------------------000000000000000
        assert_eq!(assembler.remove_data(30, 15), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000000000011111111110000000000000000000000000000000000011111111111111111111
        assert_eq!(assembler, contigs![(10, 10), (35, 20)]);
    }
    #[test]
    fn test_remove_data_single_contig1() {
        let mut assembler = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assembler.insert_data_absolute(10, 10), Ok(0));
        assert_eq!(assembler.insert_data_absolute(30, 10), Ok(1));
        assert_eq!(assembler.insert_data_absolute(50, 10), Ok(2));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000000000011111111110000000000111111111100000000001111111111
        assert_eq!(assembler, contigs![(10, 10), (10, 10), (10, 10)]);
        // Range starts within the contig hole and ends within contig data.
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // --------------------000000000000000
        assert_eq!(assembler.remove_data(20, 15), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000000000011111111110000000000000001111100000000001111111111
        assert_eq!(assembler, contigs![(10, 10), (15, 5), (10, 10)]);
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // ------------------------000000000000000
        assert_eq!(assembler.remove_data(25, 15), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000000000011111111110000000000000000000000000000001111111111
        assert_eq!(assembler, contigs![(10, 10), (30, 10)]);
    }
    #[test]
    fn test_remove_data_single_contig2() {
        let mut assembler = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assembler.insert_data_absolute(10, 10), Ok(0));
        assert_eq!(assembler.insert_data_absolute(30, 10), Ok(1));
        assert_eq!(assembler.insert_data_absolute(50, 10), Ok(2));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000000000011111111110000000000111111111100000000001111111111
        assert_eq!(assembler, contigs![(10, 10), (10, 10), (10, 10)]);
        // Range starts and ends within contig data and not all of data needs to be removed.
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // ------------------------------00000
        assert_eq!(assembler.remove_data(30, 5), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000000000011111111110000000000000001111100000000001111111111
        assert_eq!(assembler, contigs![(10, 10), (15, 5), (10, 10)]);
    }
    #[test]
    fn test_remove_data_single_contig3() {
        let mut assembler = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assembler.insert_data_absolute(10, 10), Ok(0));
        assert_eq!(assembler.insert_data_absolute(30, 10), Ok(1));
        assert_eq!(assembler.insert_data_absolute(50, 10), Ok(2));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000000000011111111110000000000111111111100000000001111111111
        assert_eq!(assembler, contigs![(10, 10), (10, 10), (10, 10)]);
        // Range starts and ends within contig data and not all of data needs to be removed.
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // -------------------------------00000
        assert_eq!(assembler.remove_data(31, 5), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000000000011111111110000000000100000111100000000001111111111
        assert_eq!(assembler, contigs![(10, 10), (10, 1), (5, 4), (10, 10)]);
    }
    #[test]
    fn test_remove_data_single_contig4() {
        let mut assembler = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assembler.insert_data_absolute(10, 10), Ok(0));
        assert_eq!(assembler.insert_data_absolute(30, 10), Ok(1));
        assert_eq!(assembler.insert_data_absolute(50, 10), Ok(2));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000000000011111111110000000000111111111100000000001111111111
        assert_eq!(assembler, contigs![(10, 10), (10, 10), (10, 10)]);
        // Range starts and ends within contig data and not all of data needs to be removed.
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // -------------------------------000000000
        assert_eq!(assembler.remove_data(31, 9), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000000000011111111110000000000100000000000000000001111111111
        assert_eq!(assembler, contigs![(10, 10), (10, 1), (19, 10)]);
    }
    #[test]
    fn test_remove_data_single_contig5() {
        let mut assembler = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assembler.insert_data_absolute(10, 10), Ok(0));
        assert_eq!(assembler.insert_data_absolute(30, 15), Ok(1));
        assert_eq!(assembler.insert_data_absolute(55, 20), Ok(2));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000000000011111111110000000000111111111111111000000000011111111111111111111
        assert_eq!(assembler, contigs![(10, 10), (10, 15), (10, 20)]);
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // --------------------------------------------0
        assert_eq!(assembler.remove_data(44, 1), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000000000011111111110000000000111111111111110000000000011111111111111111111
        assert_eq!(assembler, contigs![(10, 10), (10, 14), (11, 20)]);
    }

    // remove_data_at_head()
    // Empty Assembler
    #[test]
    fn test_remove_data_at_head_empty() {
        let mut assembler = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 0
        assert_eq!(assembler.remove_data_at_head(1), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 00
        assert_eq!(assembler.remove_data_at_head(2), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000
    }
    // Leading hole
    fn test_setup_remove_data_at_head_leading_hole() -> Assembler {
        let mut assembler = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assembler.insert_data_absolute(10, 10), Ok(0));
        assert_eq!(assembler.insert_data_absolute(30, 10), Ok(1));
        assert_eq!(assembler.insert_data_absolute(50, 10), Ok(2));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000000000011111111110000000000111111111100000000001111111111
        assert_eq!(assembler, contigs![(10, 10), (10, 10), (10, 10)]);

        assembler
    }
    #[test]
    fn test_remove_data_at_head_leading_hole1() {
        let mut assembler = test_setup_remove_data_at_head_leading_hole();
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000000000011111111110000000000111111111100000000001111111111
        // xxxxx
        assert_eq!(assembler.remove_data_at_head(5), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 0000011111111110000000000111111111100000000001111111111
        assert_eq!(assembler, contigs![(5, 10), (10, 10), (10, 10)]);
    }
    #[test]
    fn test_remove_data_at_head_leading_hole2() {
        let mut assembler = test_setup_remove_data_at_head_leading_hole();
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000000000011111111110000000000111111111100000000001111111111
        // xxxxxxxxxx
        assert_eq!(assembler.remove_data_at_head(10), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 11111111110000000000111111111100000000001111111111
        assert_eq!(assembler, contigs![(0, 10), (10, 10), (10, 10)]);
    }
    #[test]
    fn test_remove_data_at_head_leading_hole3() {
        let mut assembler = test_setup_remove_data_at_head_leading_hole();
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000000000011111111110000000000111111111100000000001111111111
        // xxxxxxxxxxxxxxx
        assert_eq!(assembler.remove_data_at_head(15), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 111110000000000111111111100000000001111111111
        assert_eq!(assembler, contigs![(0, 5), (10, 10), (10, 10)]);
    }
    #[test]
    fn test_remove_data_at_head_leading_hole4() {
        let mut assembler = test_setup_remove_data_at_head_leading_hole();
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000000000011111111110000000000111111111100000000001111111111
        // xxxxxxxxxxxxxxxxxxxx
        assert_eq!(assembler.remove_data_at_head(20), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 0000000000111111111100000000001111111111
        assert_eq!(assembler, contigs![(10, 10), (10, 10)]);
    }
    #[test]
    fn test_remove_data_at_head_leading_hole5() {
        let mut assembler = test_setup_remove_data_at_head_leading_hole();
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000000000011111111110000000000111111111100000000001111111111
        // xxxxxxxxxxxxxxxxxxxxxxxxx
        assert_eq!(assembler.remove_data_at_head(25), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 00000111111111100000000001111111111
        assert_eq!(assembler, contigs![(5, 10), (10, 10)]);
    }
    #[test]
    fn test_remove_data_at_head_leading_hole6() {
        let mut assembler = test_setup_remove_data_at_head_leading_hole();
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000000000011111111110000000000111111111100000000001111111111
        // xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        assert_eq!(assembler.remove_data_at_head(50), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 1111111111
        assert_eq!(assembler, contigs![(0, 10)]);
    }
    #[test]
    fn test_remove_data_at_head_leading_hole7() {
        let mut assembler = test_setup_remove_data_at_head_leading_hole();
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 000000000011111111110000000000111111111100000000001111111111
        // xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        assert_eq!(assembler.remove_data_at_head(60), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // empty
        assert_eq!(assembler, contigs![]);
    }
    // No leading hole
    fn test_setup_remove_data_at_head_no_leading_hole() -> Assembler {
        let mut assembler = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assembler.insert_data_absolute(0, 10), Ok(0));
        assert_eq!(assembler.insert_data_absolute(20, 10), Ok(1));
        assert_eq!(assembler.insert_data_absolute(40, 10), Ok(2));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 11111111110000000000111111111100000000001111111111
        assert_eq!(assembler, contigs![(0, 10), (10, 10), (10, 10)]);

        assembler
    }
    #[test]
    fn test_remove_data_at_head_no_leading_hole1() {
        let mut assembler = test_setup_remove_data_at_head_no_leading_hole();
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 11111111110000000000111111111100000000001111111111
        // xxxxx
        assert_eq!(assembler.remove_data_at_head(5), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 111110000000000111111111100000000001111111111
        assert_eq!(assembler, contigs![(0, 5), (10, 10), (10, 10)]);
    }
    #[test]
    fn test_remove_data_at_head_no_leading_hole2() {
        let mut assembler = test_setup_remove_data_at_head_no_leading_hole();
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 11111111110000000000111111111100000000001111111111
        // xxxxxxxxxx
        assert_eq!(assembler.remove_data_at_head(10), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 0000000000111111111100000000001111111111
        assert_eq!(assembler, contigs![(10, 10), (10, 10)]);
    }
    #[test]
    fn test_remove_data_at_head_no_leading_hole3() {
        let mut assembler = test_setup_remove_data_at_head_no_leading_hole();
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 11111111110000000000111111111100000000001111111111
        // xxxxxxxxxxxxxxx
        assert_eq!(assembler.remove_data_at_head(15), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 00000111111111100000000001111111111
        assert_eq!(assembler, contigs![(5, 10), (10, 10)]);
    }
    #[test]
    fn test_remove_data_at_head_no_leading_hole4() {
        let mut assembler = test_setup_remove_data_at_head_no_leading_hole();
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 11111111110000000000111111111100000000001111111111
        // xxxxxxxxxxxxxxxxxxxx
        assert_eq!(assembler.remove_data_at_head(20), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 111111111100000000001111111111
        assert_eq!(assembler, contigs![(0, 10), (10, 10)]);
    }
    #[test]
    fn test_remove_data_at_head_no_leading_hole5() {
        let mut assembler = test_setup_remove_data_at_head_no_leading_hole();
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 11111111110000000000111111111100000000001111111111
        // xxxxxxxxxxxxxxxxxxxxxxxxx
        assert_eq!(assembler.remove_data_at_head(25), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 1111100000000001111111111
        assert_eq!(assembler, contigs![(0, 5), (10, 10)]);
    }
    #[test]
    fn test_remove_data_at_head_no_leading_hole6() {
        let mut assembler = test_setup_remove_data_at_head_no_leading_hole();
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 11111111110000000000111111111100000000001111111111
        // xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        assert_eq!(assembler.remove_data_at_head(40), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 1111111111
        assert_eq!(assembler, contigs![(0, 10)]);
    }
    #[test]
    fn test_remove_data_at_head_no_leading_hole7() {
        let mut assembler = test_setup_remove_data_at_head_no_leading_hole();
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // 11111111110000000000111111111100000000001111111111
        // xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        assert_eq!(assembler.remove_data_at_head(50), Ok(()));
        // 0123456789|123456789|123456789|123456789|123456789|123456789|123456789|123456789
        // empty
        assert_eq!(assembler, contigs![]);
    }

    #[test]
    fn test_new() {
        let assr = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assr, contigs![]);
    }

    #[test]
    fn test_empty_add_full() {
        let mut assr = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assr.insert_data_absolute(0, 16), Ok(0));
        assert_eq!(assr, contigs![(0, 16)]);
    }

    #[test]
    fn test_empty_add_front() {
        let mut assr = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assr.insert_data_absolute(0, 4), Ok(0));
        assert_eq!(assr, contigs![(0, 4)]);
    }

    #[test]
    fn test_empty_add_back() {
        let mut assr = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assr.insert_data_absolute(12, 4), Ok(0));
        assert_eq!(assr, contigs![(12, 4)]);
    }

    #[test]
    fn test_empty_add_mid() {
        let mut assr = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assr.insert_data_absolute(4, 8), Ok(0));
        assert_eq!(assr, contigs![(4, 8)]);
    }

    #[test]
    fn test_partial_add_front() {
        let mut assr = contigs![(4, 8)];
        assert_eq!(assr.insert_data_absolute(0, 4), Ok(0));
        assert_eq!(assr, contigs![(0, 12)]);
    }

    #[test]
    fn test_partial_add_back() {
        let mut assr = contigs![(4, 8)];
        assert_eq!(assr.insert_data_absolute(12, 4), Ok(0));
        assert_eq!(assr, contigs![(4, 12)]);
    }

    #[test]
    fn test_partial_add_front_overlap() {
        let mut assr = contigs![(4, 8)];
        assert_eq!(assr.insert_data_absolute(0, 8), Ok(0));
        assert_eq!(assr, contigs![(0, 12)]);
    }

    #[test]
    fn test_partial_add_front_overlap_split() {
        let mut assr = contigs![(4, 8)];
        assert_eq!(assr.insert_data_absolute(2, 6), Ok(0));
        assert_eq!(assr, contigs![(2, 10)]);
    }

    #[test]
    fn test_partial_add_back_overlap() {
        let mut assr = contigs![(4, 8)];
        assert_eq!(assr.insert_data_absolute(8, 8), Ok(0));
        assert_eq!(assr, contigs![(4, 12)]);
    }

    #[test]
    fn test_partial_add_back_overlap_split() {
        let mut assr = contigs![(4, 8)];
        assert_eq!(assr.insert_data_absolute(10, 4), Ok(0));
        assert_eq!(assr, contigs![(4, 10)]);
    }

    #[test]
    fn test_partial_add_both_overlap() {
        let mut assr = contigs![(4, 8)];
        assert_eq!(assr.insert_data_absolute(0, 16), Ok(0));
        assert_eq!(assr, contigs![(0, 16)]);
    }

    #[test]
    fn test_partial_add_both_overlap_split() {
        let mut assr = contigs![(4, 8)];
        assert_eq!(assr.insert_data_absolute(2, 12), Ok(0));
        assert_eq!(assr, contigs![(2, 12)]);
    }

    #[test]
    fn test_rejected_add_keeps_state() {
        let mut assr = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        for c in 1..=ASSEMBLER_MAX_LOST_SEGMENT_COUNT {
            assert_eq!(assr.insert_data_absolute(c * 10, 3), Ok(c - 1));
        }
        // Maximum of allowed holes is reached
        let assr_before = assr.clone();
        assert_eq!(assr.insert_data_absolute(1, 3), Err(AssemblerError::TooManyHolesError));
        assert_eq!(assr_before, assr);
    }

    #[test]
    fn test_empty_remove_front() {
        let mut assr = contigs![];
        assert_eq!(assr.remove_contiguous_data_from_head(), 0);
    }

    #[test]
    fn test_trailing_hole_remove_front() {
        let mut assr = contigs![(0, 4)];
        assert_eq!(assr.remove_contiguous_data_from_head(), 4);
        assert_eq!(assr, contigs![]);
    }

    #[test]
    fn test_trailing_data_remove_front() {
        let mut assr = contigs![(0, 4), (4, 4)];
        assert_eq!(assr.remove_contiguous_data_from_head(), 4);
        assert_eq!(assr, contigs![(4, 4)]);
    }

    #[test]
    fn test_boundary_case_remove_front() {
        let mut vec = vec![(1, 1); ASSEMBLER_MAX_LOST_SEGMENT_COUNT];
        vec[0] = (0, 2);
        let mut assr = Assembler::from(vec);
        assert_eq!(assr.remove_contiguous_data_from_head(), 2);
        let mut vec = vec![(1, 1); ASSEMBLER_MAX_LOST_SEGMENT_COUNT];
        vec[ASSEMBLER_MAX_LOST_SEGMENT_COUNT - 1] = (0, 0);
        let exp_assr = Assembler::from(vec);
        assert_eq!(assr, exp_assr);
    }

    #[test]
    fn test_shrink_next_hole() {
        let mut assr = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assr.insert_data_absolute(100, 10), Ok(0));
        assert_eq!(assr.insert_data_absolute(50, 10), Ok(0));
        assert_eq!(assr.insert_data_absolute(40, 30), Ok(0));
        assert_eq!(assr, contigs![(40, 30), (30, 10)]);
    }

    #[test]
    fn test_join_two() {
        let mut assr = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assr.insert_data_absolute(10, 10), Ok(0));
        assert_eq!(assr.insert_data_absolute(50, 10), Ok(1));
        assert_eq!(assr.insert_data_absolute(15, 40), Ok(0));
        assert_eq!(assr, contigs![(10, 50)]);
    }

    #[test]
    fn test_join_two_reversed() {
        let mut assr = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assr.insert_data_absolute(50, 10), Ok(0));
        assert_eq!(assr.insert_data_absolute(10, 10), Ok(0));
        assert_eq!(assr.insert_data_absolute(15, 40), Ok(0));
        assert_eq!(assr, contigs![(10, 50)]);
    }

    #[test]
    fn test_join_two_overlong() {
        let mut assr = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assr.insert_data_absolute(50, 10), Ok(0));
        assert_eq!(assr.insert_data_absolute(10, 10), Ok(0));
        assert_eq!(assr.insert_data_absolute(15, 60), Ok(0));
        assert_eq!(assr, contigs![(10, 65)]);
    }

    #[test]
    fn test_iter_empty() {
        let assr = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        let segments: Vec<_> = assr.iter_data(10).collect();
        assert_eq!(segments, vec![]);
    }

    #[test]
    fn test_iter_full() {
        let mut assr = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assr.insert_data_absolute(0, 16), Ok(0));
        let segments: Vec<_> = assr.iter_data(10).collect();
        assert_eq!(segments, vec![(10, 26)]);
    }

    #[test]
    fn test_iter_offset() {
        let mut assr = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assr.insert_data_absolute(0, 16), Ok(0));
        let segments: Vec<_> = assr.iter_data(100).collect();
        assert_eq!(segments, vec![(100, 116)]);
    }

    #[test]
    fn test_iter_one_front() {
        let mut assr = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assr.insert_data_absolute(0, 4), Ok(0));
        let segments: Vec<_> = assr.iter_data(10).collect();
        assert_eq!(segments, vec![(10, 14)]);
    }

    #[test]
    fn test_iter_one_back() {
        let mut assr = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assr.insert_data_absolute(12, 4), Ok(0));
        let segments: Vec<_> = assr.iter_data(10).collect();
        assert_eq!(segments, vec![(22, 26)]);
    }

    #[test]
    fn test_iter_one_mid() {
        let mut assr = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assr.insert_data_absolute(4, 8), Ok(0));
        let segments: Vec<_> = assr.iter_data(10).collect();
        assert_eq!(segments, vec![(14, 22)]);
    }

    #[test]
    fn test_iter_one_trailing_gap() {
        let assr = contigs![(4, 8)];
        let segments: Vec<_> = assr.iter_data(100).collect();
        assert_eq!(segments, vec![(104, 112)]);
    }

    #[test]
    fn test_iter_two_split() {
        let assr = contigs![(2, 6), (4, 1)];
        let segments: Vec<_> = assr.iter_data(100).collect();
        assert_eq!(segments, vec![(102, 108), (112, 113)]);
    }

    #[test]
    fn test_iter_three_split() {
        let assr = contigs![(2, 6), (2, 1), (2, 2)];
        let segments: Vec<_> = assr.iter_data(100).collect();
        assert_eq!(segments, vec![(102, 108), (110, 111), (113, 115)]);
    }

    #[test]
    fn test_issue_694() {
        let mut assr = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assr.insert_data_absolute(0, 1), Ok(0));
        assert_eq!(assr.insert_data_absolute(2, 1), Ok(1));
        assert_eq!(assr.insert_data_absolute(1, 1), Ok(0));
    }

    #[test]
    fn test_add_then_remove_front() {
        let mut assr = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assr.insert_data_absolute(50, 10), Ok(0));
        assert_eq!(assr.insert_then_remove_contiguous_data_from_head(10, 10), Ok(0));
        assert_eq!(assr, contigs![(10, 10), (30, 10)]);
    }

    #[test]
    fn test_add_then_remove_front_at_front() {
        let mut assr = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assr.insert_data_absolute(50, 10), Ok(0));
        assert_eq!(assr.insert_then_remove_contiguous_data_from_head(0, 10), Ok(10));
        assert_eq!(assr, contigs![(40, 10)]);
    }

    #[test]
    fn test_add_then_remove_front_at_front_touch() {
        let mut assr = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        assert_eq!(assr.insert_data_absolute(50, 10), Ok(0));
        assert_eq!(assr.insert_then_remove_contiguous_data_from_head(0, 50), Ok(60));
        assert_eq!(assr, contigs![]);
    }

    #[test]
    fn test_add_then_remove_front_at_front_full() {
        let mut assr = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        for c in 1..=ASSEMBLER_MAX_LOST_SEGMENT_COUNT {
            assert_eq!(assr.insert_data_absolute(c * 10, 3), Ok(c - 1));
        }
        // Maximum of allowed holes is reached
        let assr_before = assr.clone();
        assert_eq!(assr.insert_then_remove_contiguous_data_from_head(1, 3), Err(AssemblerError::TooManyHolesError));
        assert_eq!(assr_before, assr);
    }

    #[test]
    fn test_add_then_remove_front_at_front_full_offset_0() {
        let mut assr = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
        for c in 1..=ASSEMBLER_MAX_LOST_SEGMENT_COUNT {
            assert_eq!(assr.insert_data_absolute(c * 10, 3), Ok(c -1));
        }
        assert_eq!(assr.insert_then_remove_contiguous_data_from_head(0, 3), Ok(3));
    }

    // Test against an obviously-correct but inefficient bitmap impl.
    #[test]
    fn test_random() {
        use rand::Rng;

        const MAX_INDEX: usize = 256;

        for max_size in [2, 5, 10, 100] {
            for _ in 0..300 {
                //println!("===");
                let mut assr = Assembler::new(ASSEMBLER_MAX_LOST_SEGMENT_COUNT);
                let mut map = [false; MAX_INDEX];

                for _ in 0..60 {
                    let offset = rand::thread_rng().gen_range(0..MAX_INDEX - max_size - 1);
                    let size = rand::thread_rng().gen_range(1..=max_size);

                    //println!("add {}..{} {}", offset, offset + size, size);
                    // Real impl
                    let res = assr.insert_data_absolute(offset, size);

                    // Bitmap impl
                    let mut map2 = map;
                    map2[offset..][..size].fill(true);

                    let mut contigs = vec![];
                    let mut hole: usize = 0;
                    let mut data: usize = 0;
                    for b in map2 {
                        if b {
                            data += 1;
                        } else {
                            if data != 0 {
                                contigs.push((hole, data));
                                hole = 0;
                                data = 0;
                            }
                            hole += 1;
                        }
                    }

                    // Compare.
                    let wanted_res = if contigs.len() > ASSEMBLER_MAX_LOST_SEGMENT_COUNT {
                        Err(AssemblerError::TooManyHolesError)
                    } else {
                        Ok(size)
                    };
                    if wanted_res.is_err() {
                        assert!(res.is_err());
                    } else {
                        assert!(res.is_ok());
                    }
                    if res.is_ok() {
                        map = map2;
                        assert_eq!(assr, Assembler::from(contigs));
                    }
                }
            }
        }
    }
}
