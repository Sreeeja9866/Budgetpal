import heapq
from datetime import datetime
from flask_login import UserMixin

# User model
class User(UserMixin):
    """User model for Flask-Login"""
    def __init__(self, user_id, fullname, username, email):
        self.id = user_id
        self.fullname = fullname
        self.username = username
        self.email = email

    def __repr__(self):
        return f"<User id={self.id}, fullname='{self.fullname}', username='{self.username}', email='{self.email}'>"

# SavingsGoal class for priority queue
class SavingsGoal:
    def __init__(self, id, name, target_amount, current_amount, target_date, priority):
        self.id = id
        self.name = name
        self.target_amount = target_amount
        self.current_amount = current_amount
        self.target_date = datetime.strptime(target_date, '%Y-%m-%d').date() if isinstance(target_date, str) else target_date
        self.priority = priority

    def __lt__(self, other):
        if self.priority != other.priority:
            return self.priority < other.priority
        return self.target_date < other.target_date

class SavingsGoalPriorityQueue:
    def __init__(self):
        self.queue = []

    def add_goal(self, goal):
        heapq.heappush(self.queue, goal)

    def get_highest_priority_goal(self):
        return heapq.heappop(self.queue) if self.queue else None

    def peek_highest_priority_goal(self):
        return self.queue[0] if self.queue else None

    def update_goal(self, goal):
        self.queue = [g for g in self.queue if g.id != goal.id]
        heapq.heapify(self.queue)
        heapq.heappush(self.queue, goal)

    def get_all_goals(self):
        return sorted(self.queue)

    def clear(self):
        self.queue.clear()
