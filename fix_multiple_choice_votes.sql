-- Fix for multiple choice voting in room polls
-- The unique constraint 'unique_single_vote' on (poll_id, user_id) prevents 
-- users from selecting multiple options in multiple-choice polls.

-- Run this SQL script in phpMyAdmin to fix the issue:

-- Step 1: Drop the current unique constraint
ALTER TABLE `room_poll_votes` DROP INDEX `unique_single_vote`;

-- Step 2: Add a new unique constraint that allows multiple options per user
-- This constraint ensures a user can't vote for the SAME option twice, 
-- but CAN vote for multiple different options in the same poll
ALTER TABLE `room_poll_votes` 
ADD UNIQUE KEY `unique_vote_per_option` (`poll_id`, `user_id`, `option_id`);

-- After running this script, multiple choice polls will work correctly!
